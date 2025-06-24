-- Database Setup

-- Create schema
CREATE SCHEMA IF NOT EXISTS tlddns;

-- Name Server Types
-- customer: NOTIFY sent by customer hidden primary
-- incoming: NOTIFY by inbound name server of DNS provider
-- distribution: NOTIFY by distribution name server of DNS provider (optional)
-- secondary: NOTIFY by the (anycast) nameserver that serves public queries
CREATE TYPE nameserver_type AS ENUM ('customer', 'incoming', 'distribution','secondary');

-- Name Server Status
-- disabled: nameserver is not shown in customer GUI (historic, not yet deployed)
-- production: nameserver is shown in customer menu and is active in the anycast cloud and receiving queries
-- maintenance: nameserver is shown in customer menu as "under maintenance", and is currenlty not active in the anycast cloud and not receiving queries
CREATE TYPE nameserver_status AS ENUM ('disabled', 'production', 'maintenance');

-- Track serials and calculate zone propagation delays
-- distribution_lag: lag between zone was received on the distribution name server of RcodeZero and the anycast location
-- incoming_lag: lag between zone was received on the incoming name server of RcodeZero and the anycast location
-- customer lag: lag between customer hidden primary name server of RcodeZero and the anycast location
-- A _lag of 0 means, that this kind of lag makes no sense. For example, the incoming name server can only have a
--   customer_lag - hence, distribution_lag and distribution_lag are set to 0.
-- A _lag of -1 seconds means, that the serial logger could not find a reference for this serial in its cache.
--   This can for example happen if the NOTIFY from the distribution name server arrives after the NOTIFY from the
--   Anycast location, or if the serial-logger restarted and missed the NOTIFY from the customer name server but
--   receives the NOTIFY from the Anycast locations, for that specific zone and serial.
-- This table can become quiet big with plenty ol locations, zones and serials. Hence, the table needs periodical
-- cleanup.
CREATE TABLE tlddns.serials (
    id BIGSERIAL PRIMARY KEY,
    srcip TEXT,
    zone TEXT NOT NULL,
    received_at TIMESTAMP NOT NULL DEFAULT NOW(),
    serial BIGINT NOT NULL,
    hostname TEXT,
    loc TEXT,
    dsc_name TEXT,
    ns_type nameserver_type,
    distribution_lag interval,
    incoming_lag interval,
    customer_lag interval,
    UNIQUE (srcip,zone,serial)
);
CREATE INDEX serials_serial_idx ON tlddns.serials (serial);
CREATE INDEX serials_srcip_idx ON tlddns.serials (srcip);
CREATE INDEX serials_zone_idx ON tlddns.serials (zone);
CREATE INDEX serials_hostname_idx ON tlddns.serials (hostname);
CREATE INDEX serials_loc_idx ON tlddns.serials (loc);
CREATE INDEX serials_dsc_name_idx ON tlddns.serials (dsc_name);
CREATE INDEX serials_ns_idx ON tlddns.serials (ns_type);

-- The list of the nameservers of the DNS provider. If the DNS provider adds o removes nameservers, that list should be updated
-- and the serial-logger must be restarted.
CREATE TABLE tlddns.nameservers (
    id SERIAL PRIMARY KEY,
    ip4 TEXT UNIQUE,
    ip6 TEXT UNIQUE,
    hostname TEXT NOT NULL UNIQUE,
    loc TEXT NOT NULL,
    dsc_name TEXT NOT NULL,
    ns_type nameserver_type NOT NULL,
    status nameserver_status NOT NULL
);
CREATE INDEX nameservers_ip4_idx ON tlddns.nameservers (ip4);
CREATE INDEX nameservers_ip6_idx ON tlddns.nameservers (ip6);
CREATE INDEX nameservers_ns_type_idx ON tlddns.nameservers (ns_type);

-- The list of the priamry name serves of the customer.
CREATE TABLE tlddns.customer_nameservers (
    id SERIAL PRIMARY KEY,
    ip text,
    zone text NOT NULL,
    accountname text NOT NULL
);
CREATE INDEX customer_nameservers_ip_idx ON tlddns.customer_nameservers USING btree (ip);
CREATE INDEX customer_nameservers_zone_idx ON tlddns.customer_nameservers USING btree (zone);

-- For every zone and serial the SLA metrics will be calulated and stored in this table. The content in this table
-- can be kept for long time and the source data in the 'serials' table can be deleted after 1 day.
CREATE TABLE tlddns.slas (
    id integer NOT NULL,
    zone text,
    serial bigint,
    min_lag interval,
    max_lag interval,
    avg_lag interval,
    median_lag interval,
    percentile_90_lag interval,
    ns_count integer,
    calculated_at timestamp with time zone
);
CREATE INDEX idx_serials_zone_received_at ON tlddns.serials USING btree (zone, received_at);
CREATE INDEX idx_slas_calculated_at ON tlddns.slas USING btree (calculated_at);

-- Create a user and grant permissions
GRANT USAGE ON SCHEMA tlddns TO serial_logger;

GRANT ALL PRIVILEGES ON tlddns.serials TO serial_logger;
GRANT USAGE ON tlddns.serials_id_seq TO serial_logger;

GRANT ALL PRIVILEGES ON tlddns.nameservers TO serial_logger;
GRANT USAGE ON tlddns.nameservers_id_seq TO serial_logger;

GRANT ALL PRIVILEGES ON tlddns.customer_nameservers TO serial_logger;
GRANT USAGE ON tlddns.customer_nameservers_id_seq TO serial_logger;

GRANT ALL PRIVILEGES ON tlddns.slas TO serial_logger;
GRANT USAGE ON tlddns.slas_id_seq TO serial_logger;
