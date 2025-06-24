#!/usr/bin/env python3

"""
LICENSE http://www.apache.org/licenses/LICENSE-2.0
"""

# A daemon which receives and processes NOTIFYs
# Based on https://gist.github.com/pklaus/b5a7876d4d2cf7271873

# apt install python3-psycopg2 python3-dnslib
import argparse
from datetime import datetime, timedelta
import sys
import time
import threading
import traceback
import socketserver
import signal
import queue
import struct
import psycopg2.pool
from psycopg2.extras import RealDictCursor
from psycopg2.extras import execute_values
from dnslib import *
import yaml
import statistics
import logging
from expiringdict.expiringdict import ExpiringDict


### Global Variables
LOG_FILE="/usr/local/bin/serial-logger/log.log" # LOG_FILE="log.log"
METRIC_FILE="/usr/local/bin/serial-logger/metrics.txt" # METRIC_FILE="metrics.txt"
CONFIG_FILE="/usr/local/bin/serial-logger/credentials.yaml" # CONFIG_FILE="credentials.yaml"
MAX_EVENT_INSERT = 200   # INSERT after having received that many events even if we have not reached the MAX_WAIT_INSERT time
MAX_WAIT_INSERT = 10     # Wait that many seconds before doing an INSERT even if we have less than MAX_EVENT_INSERT events
SLA_INTERVAL= 60         # Update the SLAs every SLA_INTERVAL seconds
SHUTDOWN_QUEUE_TIMEOUT = 10 # Timeout in seconds to wait for the worker threads to finish after shutdown is requested
NUM_WORKER_TREADS = 1    # List of DB worker threads


# *** Gloabal Variables
last_sla_exec= 0      # Last time we updated the SLAs
pool = {} # Connection pool for PostgreSQL databases
metrics={}  # Dictionary to store metrics for Checkmk
servers = []  # List of receive servers
worker_threads = []
# for big INSERTs we get deadlocks when doing parallel INSERTs from threads. Hence we serialize them.
# As the inserts take some time for all DBs we serialize per DB
db_lock={}
request_queue = queue.Queue() # Create a Queue for serializing requests
nameservers = {}  # Nameservers dictionary fetched from DB
customer_nameservers = {}
# Reference serials to calculate the lag
customer_serials = {}
incoming_serials = {}
distribution_serials = {}
# Track the BGP status of the anycast servers
bgp_status = {}
# Create a lock object for printing to stdout, so that threads are not within in others print statement
print_lock = threading.Lock()
# event to signal shutdown to DB-worker threads
shutdown_event = threading.Event()




logging.basicConfig(
    level=logging.INFO,  # Log-Level: DEBUG, INFO, WARNING, ERROR, CRITICAL
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),  
        logging.StreamHandler()          
    ]
)
logger = logging.getLogger(__name__)


#   ************ Class definitions ************


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        try:
            data = self.get_data()
            self.send_data(handle_dns_request(data,self.client_address[0]))
        except Exception:
            traceback.print_exc(file=sys.stderr)

class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            thread_safe_print("INFO Wrong size of TCP packet from",self.client_address[0])
        elif sz > len(data) - 2:
            thread_safe_print("INFO Too big TCP packet or non-DNS packet from",self.client_address[0])
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)

class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0]

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

class IPv4ThreadingTCPServer(socketserver.ThreadingTCPServer):

    def server_bind(self):
        # Allow multiple sockets to bind to the same port, to allow daemon restart
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        super().server_bind()

class IPv6ThreadingTCPServer(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        # Allow IPv6 only
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        # Allow multiple sockets to bind to the same port, to allow daemon restart
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        super().server_bind()

class IPv6ThreadingUDPServer(socketserver.ThreadingUDPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        # Allow IPv6 only
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()

#  ************** End of Class definitions *************

#   ************ Function definitions ******************
def load_db_config(config_file="credentials.yaml"):
    global pool
    with open(config_file, "r") as file:
        config = yaml.safe_load(file)["databases"]
    for db_name, db_config in config.items():
        if db_config['in_operation']:
            pool[db_name]= psycopg2.pool.ThreadedConnectionPool(2, 20, user=db_config['user'], password=db_config['password'], host=db_config['host'], port=db_config['port'], database=db_config['database'])


def fetch_nameservers():
    # Fetch nameservers from the database and populate the nameservers dictionary
    # Supose that tlddns.nameservers in all databases are identical and has the same structure
    conn = pool['prod'].getconn()
    conn.set_session(autocommit=True)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT ip4, ip6, hostname, loc, dsc_name, ns_type, status FROM tlddns.nameservers;")
            rows = cursor.fetchall()

            # Process each row
            for row in rows:
                nameservers[row['ip4']] = {
                    'hostname': row['hostname'],
                    'loc':      row['loc'],
                    'dsc_name': row['dsc_name'],
                    'ns_type':  row['ns_type'],
                    'status':   row['status'],
                }
                nameservers[row['ip6']] = {
                    'hostname': row['hostname'],
                    'loc':      row['loc'],
                    'dsc_name': row['dsc_name'],
                    'ns_type':  row['ns_type'],
                    'status':   row['status'],
                }
                # As we do not know better, we have to treat locations as production
                bgp_status[row['hostname']] = 1

    except Exception as e:
        logger.error(f'ERROR Exception {type(e).__name__} in fetch_nameservers: {e}')
    finally:
        pool['prod'].putconn(conn)
    logger.info(f"Fetched nameservers from DB. {nameservers}")
    logger.info(f"Set bgp_status to 1 for all name servers. {bgp_status}")    

def fetch_customer_nameservers():
    conn = pool['prod'].getconn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT ip, zone, accountname FROM tlddns.customer_nameservers;")
            rows = cursor.fetchall()
            # We create an entry for every legal combination of IP and zone and use 1 as dummy entry.
            for row in rows:
                if row['ip'] not in customer_nameservers:
                    customer_nameservers[row['ip']] = {}
                customer_nameservers[row['ip']][row['zone']] = row['accountname'];

    except Exception as e:
        logger.error(f'ERROR Exception {type(e).__name__} in fetch_customer_nameservers: {e}')
    finally:
        pool['prod'].putconn(conn)
    logger.info(f"Fetched customer_nameservers from DB. {customer_nameservers}")

def process_queue():
    global last_sla_exec
    thread_name = threading.current_thread().name  # Get the current thread's name
    last_db_insert = time.time()
    events_queued_for_insert = []

    while True:
        time.sleep(1)
        last_sla_exec +=1
        queue_size = request_queue.qsize()
        metrics["Incoming_notify_per_second"].append(queue_size)
        if queue_size > 0:
            # Fetch all items from the queue
            while not request_queue.empty():
                src,zone,serial,ts = request_queue.get()
                if src not in nameservers:
                # Maybe it is from a customer
                    if src in customer_nameservers:
                        if zone not in customer_nameservers[src]:
                            logger.warning(f"---- {thread_name} NOTIFY source {src} is not allowed to send NOTIFYs for zone {zone}... ignoring")
                            continue
                    else:
                        logger.warning(f"---- {thread_name} NOTIFY source {src} is unknown (not in nameserver and not in customer_nameservers table). Update nameserver tables and reload serial-logger.py! Ignoring this NOTIFY!")
                        continue
                events_queued_for_insert.append(process_notify(src,zone,serial,ts))

        else:
            logger.info(f"---- {thread_name} Queue is empty!! No packet is recieved in last second!!")

        if (len(events_queued_for_insert) >= MAX_EVENT_INSERT) or shutdown_event.is_set() or ((time.time() - last_db_insert) > MAX_WAIT_INSERT):
            insert_into_db(events_queued_for_insert)
            last_db_insert =time.time()
            events_queued_for_insert=[]
            if last_sla_exec >= SLA_INTERVAL:
                update_slas_thread()
                last_sla_exec=0
            
            if shutdown_event.is_set():
                logger.info(f"---- {thread_name} Exiting thread as shutdown_event detected")
                break

def insert_into_db(events_queued_for_insert):

        start_time_all=time.time()
        thread_name = threading.current_thread().name  # Get the current thread's name
        metrics["Number_of_notify_for_bulk_insertion"].append(len(events_queued_for_insert))
        if len(events_queued_for_insert) == 0:
            logger.info(f"---- {thread_name} No events in events_queued_for_insert, doing nothing.")
            return
        else:
            logger.info(f"---- {thread_name} {len(events_queued_for_insert)} events in events_queued_for_insert, preparing INSERT query ...")

        query = "INSERT INTO tlddns.serials (srcip,zone,serial,received_at, hostname,loc,dsc_name,ns_type, customer_lag,incoming_lag,distribution_lag, status) " \
                "VALUES %s ON CONFLICT DO NOTHING"

        for p in  pool.keys():
            start_time = time.time()
            conn = pool[p].getconn()
            conn.set_session(autocommit=True)
            try:
                # with db_test_lock:
                with db_lock[p]:
                    with conn.cursor() as cursor:
                        total_affected_rows = 0
                        for i in range(0,len(events_queued_for_insert), MAX_EVENT_INSERT):
                            batch = events_queued_for_insert[i:i + MAX_EVENT_INSERT]  # Extract batch
                            execute_values(cursor, query, batch, page_size=MAX_EVENT_INSERT)
                            total_affected_rows += cursor.rowcount  # Accumulate affected row
                        
            except Exception as e:
                    logger.error(f'{thread_name} ERROR executing DB INSERT into {p}: {e}')
            finally:
                pool[p].putconn(conn)
            elapsed_time = (time.time() - start_time)
            metrics[f"{p}_db_inserted_rows"].append(total_affected_rows)
            metrics[f"{p}_db_insert_exec_time_(sec.)"].append(elapsed_time)
            
            logger.info(f"---- {thread_name} DB INSERT {p} DONE {len(events_queued_for_insert)} events in {elapsed_time:.3f}s: affected_rows = {total_affected_rows}")       
          
        elapsed_time = (time.time() - start_time_all)
        logger.info(f"---- {thread_name} DB INSERT for All databeses finished after {elapsed_time:.3f}s")

def update_slas_thread():
    sla_query = """
    INSERT INTO tlddns.slas 
        (zone,serial,min_lag,max_lag,avg_lag,median_lag,percentile_90_lag,ns_count,calculated_at)
    SELECT
        zone,
        serial,
        MIN(incoming_lag) AS min,
        MAX(incoming_lag) AS max,
        AVG(incoming_lag) AS avg,
        PERCENTILE_CONT(0.5) WITHIN GROUP ( ORDER BY incoming_lag ) AS median,
        PERCENTILE_CONT(0.9) WITHIN GROUP ( ORDER BY incoming_lag ) AS percentile_90,
        count(*) AS ns_count,
        now()
    FROM(
        SELECT dsc_name, zone, serial, min(incoming_lag) AS incoming_lag
        FROM tlddns.serials
        WHERE zone = %s
            AND serial = %s
            AND zone <> 'bgp'
            AND dsc_name NOT LIKE %s
            AND ns_type = 'secondary'
            AND incoming_lag >=  interval '0s'
        GROUP BY dsc_name, ZONE, serial
    ) d
    GROUP BY ZONE,  serial ON CONFLICT (ZONE, serial) DO
    UPDATE
    SET
    min_lag = EXCLUDED.min_lag,
    max_lag = EXCLUDED.max_lag,
    avg_lag = EXCLUDED.avg_lag,
    median_lag = EXCLUDED.median_lag,
    percentile_90_lag = EXCLUDED.percentile_90_lag,
    ns_count = EXCLUDED.ns_count,
    calculated_at = EXCLUDED.calculated_at;
"""
    thread_name = threading.current_thread().name  # Get the current thread's name
    # while True:
        # time.sleep(SLA_INTERVAL)  
    for env in pool.keys():
        logger.info(f"{thread_name} {env} Updating SLAs ...")

        conn = pool[env].getconn()
        conn.set_session(autocommit=True)
        try:
            with db_lock[env]:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    start_time = time.time()
                    cursor.execute("SELECT distinct zone, serial FROM tlddns.serials WHERE zone <> 'bgp' AND ns_type = 'secondary' AND dsc_name NOT LIKE 'Test%' AND incoming_lag >=  interval '0s' AND received_at >= (SELECT max(calculated_at) FROM tlddns.slas)")
                    rows = cursor.fetchall()
                    update_rows = len(rows)
                    if update_rows == 0:
                        logger.info(f"{thread_name} {env} Updating SLAs ... nothing to do.")
                    else:
                        logger.info(f"{thread_name} {env} Updating SLAs ... found {update_rows} zone_serial tuples to update.")
                        for row in rows:
                            zone = row['zone']
                            serial = int(row['serial'])
                            logger.info(f"{thread_name} {env} Updating SLAs for zone {zone} serial {serial}")
                            cursor.execute(sla_query, (zone, serial, 'Test%')) # Test% written into SQL query confuses psycopg2
                            if cursor.rowcount != 1:
                                logger.error(f"{thread_name} {env} ERROR Updated SLAs for zone {zone} serial {serial} affected_rows should be 1 but is {cursor.rowcount}. Maybe reference values are missing in DB. See insert command: {interpolated_query}")
                        elapsed_time = (time.time() - start_time)
                        metrics[f"{env}_db_SLA_update_exec_time_(sec.)"].append(elapsed_time)
                        logger.info(f"{thread_name} {env} Updated {update_rows} SLAs in {elapsed_time}s")
        except Exception as e:
            logger.error(f'{thread_name} {env}ERROR executing DB QUERY on DEV: {e}')
        finally:
            pool[env].putconn(conn)
    write_metric()
    

def reset_metrics():
    global metrics
    metrics.clear()
    metrics["Incoming_notify_per_second"]=[]
    metrics["Number_of_notify_for_bulk_insertion"]=[]
    for p in pool.keys():
        metrics[f"{p}_db_insert_exec_time_(sec.)"]=[]
        metrics[f"{p}_db_inserted_rows"]=[]
        metrics[f"{p}_db_SLA_update_exec_time_(sec.)"]=[]
    
def write_metric():
    """
    Writes a metric to the Checkmk log file for monitoring.
    """
    try:
        with open(METRIC_FILE, "w") as f:
            for key, values in metrics.items():
                if len(values) >0:
                    if "exec_time" in key:
                        f.write(f"{key}={statistics.mean(values)};;1;{min(values)};{max(values)}\n")
                    else:
                        f.write(f"{key}={statistics.mean(values)};;;{min(values)};{max(values)}\n")
    except Exception as e:
        logger.error(f"Error writing to log file: {e}")
    reset_metrics()

def remove_trailing_period(s):
    if s.endswith('.'):
        return s[:-1]  # Remove the last character
    return s

def handle_dns_request(data,srcip):
    # NOTE: For every incoming request, a new thread will be started by the respective "server"
    received_at = datetime.now()
    request = DNSRecord.parse(data)

    qname=remove_trailing_period(str( request.get_q().get_qname() ))

    if OPCODE.get(request.header.opcode) != 'NOTIFY':
      logger.info(f"Rejecting {OPCODE.get(request.header.opcode)} from {srcip} for zone {qname}")
      # Generate a response from the request
      reply = request.reply()
      # Set rcode=REFUSED
      reply.header.set_rcode(RCODE.REFUSED)
      reply.header.set_aa(0)
      reply.header.set_ra(0)
      reply.header.set_ad(0)
      return reply.pack()

    if len(request.rr) == 0:
      logger.info(f"Request from {srcip} for zone {qname} does not contain a SOA record ... ignoring")
    else:
      rr=request.rr[0]
      rtype=QTYPE.get(rr.rtype)
      if rtype != "SOA":
        logger.info(f"Request from {srcip} for zone {qname} does not have SOA in Answer section but does have {rtype} instead ... ignoring")
      else:
        rname=rr.rname
        if rname != qname:
          logger.info(f"Request from {srcip} for zone {qname} rname {rname} does not match qname {qname} ... ignoring")
        else:
          serial=rr.rdata.times[0]
          # We do not process the NOTIFY immediately. We put the info into a queue and then send back the response as long as we have the socket available
          request_queue.put( (srcip,str(qname),serial,received_at) )
          queue_size = request_queue.qsize()
          logger.info(f"Request from  {srcip} for zone {qname} rtype {QTYPE.get(rr.rtype)} rname {rname} serial {serial} {received_at} received_at ... added to queue, {queue_size} items in the queue")

    # Generate and send back a positive response for the NOTIFY
    reply = request.reply()
    #thread_safe_print("---- Reply:\n", reply)
    return reply.pack()

def signal_handler(sig, frame):
    logger.info("signal_handler: Received shutdown signal.")
    shutdown_event.set()
    shutdown()
    sys.exit(0)  # Exit the program after cleanup

def process_notify(src, zone, serial, ts):
    
    def cache_serials(serials_dict, zone, serial, ts):
        """ Hilfsfunktion zur Verwaltung von Serial-Timestamps mit ExpiringDict """
        if zone not in serials_dict:
            serials_dict[zone] = ExpiringDict(max_len=1000, max_age_seconds=36000)
        if serial not in serials_dict[zone]:
            serials_dict[zone][serial] = ts

    # Default values ​​for delays
    customer_lag = incoming_lag = distribution_lag = timedelta()
    
    # Processing depending on source type
    if src in customer_nameservers:
        hostname = customer_nameservers[src][zone]  # Pseudo-Hostname
        loc      = ""
        dsc_name = src
        ns_type  = "customer"
        cache_serials(customer_serials, zone, serial, ts)  
    elif src in nameservers:
        ns_info = nameservers[src]
        hostname = ns_info['hostname']
        loc=ns_info['loc']
        dsc_name=ns_info['dsc_name']
        ns_type= ns_info['ns_type']

        if ns_type in ['incoming', 'distribution']:
            serials_dict = incoming_serials if ns_type == 'incoming' else distribution_serials
            cache_serials(serials_dict, zone, serial, ts)

            # Calculate delays
            customer_lag = ts - customer_serials[zone][serial] if zone in customer_serials and serial in customer_serials[zone] else '-00:00:01'
            if ns_type == 'distribution':
                incoming_lag = ts - incoming_serials[zone][serial] if zone in incoming_serials and serial in incoming_serials[zone] else '-00:00:01'

        elif ns_type == 'secondary':
            if  zone in customer_serials and serial not in customer_serials[zone]:
                # If the serial is already in customer_serials, we use it to calculate the lag
                logger.warning(f"Warnign the last inserted serial for {zone} is {max(customer_serials[zone].keys())} but we received a new serial {serial} for {src}.")
            customer_lag = ts - customer_serials[zone][serial] if zone in customer_serials and serial in customer_serials[zone] else '-00:00:01'
            incoming_lag = ts - incoming_serials[zone][serial] if zone in incoming_serials and serial in incoming_serials[zone] else '-00:00:01'
            distribution_lag = ts - distribution_serials[zone][serial] if zone in distribution_serials and serial in distribution_serials[zone] else '-00:00:01'

    if zone == "bgp":
        bgp_status[hostname] = serial % 2
        customer_lag = incoming_lag = distribution_lag = timedelta()

    status = 'maintenance' if src in nameservers and nameservers[src]['ns_type'] == 'secondary' and bgp_status.get(hostname) == 0 else 'production'

    # Save event for insertion into the database
    return ( src,zone,serial,ts,hostname, loc, dsc_name, ns_type, customer_lag, incoming_lag, distribution_lag, status)

def shutdown():
        logger.info("Starting shutdown sequence ...")

        # Step 1: Shutdown the servers
        for s in servers:
            logger.info("Shutting down receiver thread ...")
            s.shutdown()
        logger.info("Receiver shutdown complete.")

        for i in range(SHUTDOWN_QUEUE_TIMEOUT):
            # Step 2: Check if the worker terminates themselves
            if all(not thread.is_alive() for thread in worker_threads):
                logger.info("All db workers have finished.")
                break
            else:
                logger.info("Waiting for db workers to finish...")
                time.sleep(1) 

        logger.info("Shutting down.")

#   ************ End of Function definitions *************





def main():
    load_db_config(CONFIG_FILE)
    for p in pool.keys():
        db_lock[p]= threading.Lock()

    reset_metrics()

    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
    parser.add_argument('--port', default=5053, type=int, help='The port to listen on.')
    parser.add_argument('--tcp4', action='store_true', help='Listen to IPv4 TCP connections.')
    parser.add_argument('--udp4', action='store_true', help='Listen to IPv4 UDP datagrams.')
    parser.add_argument('--tcp6', action='store_true', help='Listen to IPv6 TCP connections.')
    parser.add_argument('--udp6', action='store_true', help='Listen to IPv6 UDP datagrams.')

    args = parser.parse_args()
    if not (args.udp4 or args.tcp4 or args.udp6 or args.tcp6): parser.error("Please select at least one of --udp4, --tcp4, --udp6  or --tcp6.")
    logger.info(f"Starting serial-logger with args: {args}")
    

    # Register signal handlers for SIGINT (CTRL+C) and SIGTERM
    #signal.signal(signal.SIGINT, signal_handler)  # Handle CTRL+C
    signal.signal(signal.SIGTERM, signal_handler)  # Handle termination signals (kill)

    # Read nameservers from DB into hash and use it to enrich serials table.
    # On updates on the nameservers table, puppet should restart serial_logger gracefully
    fetch_nameservers()
    fetch_customer_nameservers()

    # TCPServer blocks, so other TCP requests are blocked if a TCP connection hangs.
    # ThreadedTCPServer works great, but then the postgresql INSERT code must be thread safe.
    # Knot supposrts only NOTIFYs  per TCP.
    #if args.udp: servers.append(socketserver.UDPServer(('', args.port), UDPRequestHandler))
    if args.udp4: servers.append(socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp4: servers.append(IPv4ThreadingTCPServer(('', args.port), TCPRequestHandler))
    if args.udp6: servers.append(IPv6ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp6: servers.append(IPv6ThreadingTCPServer(('', args.port), TCPRequestHandler))

    # Create worker threads
    # We use only one worker thread, in case of using multiple threads take care of metrics like "Incoming_notify_per_second"
    for i in range(NUM_WORKER_TREADS):  # Create a fixed number of worker threads
        worker = threading.Thread(target=process_queue, name=f"Thread-DB-Worker-{i}")
        worker.daemon = True
        worker.start()
        worker_threads.append(worker)

    i=0
    for s in servers:
        thread = threading.Thread(target=s.serve_forever, name=f"Thread-Receiver-{i}")  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        logger.info(f"{s.RequestHandlerClass.__name__[:3]} server loop running in thread: {thread.name}")
        i = i + 1

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt exception ... passing and starting shutdown code")
        shutdown_event.set()
        pass
    finally:
        shutdown()

if __name__ == '__main__':
    main()
