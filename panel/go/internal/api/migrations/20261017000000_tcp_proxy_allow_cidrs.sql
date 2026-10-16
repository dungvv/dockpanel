-- Optional source allow-list per TCP proxy, rendered as nginx stream
-- `allow …; deny all;`. Empty = open to anyone (the previous behaviour).
ALTER TABLE tcp_proxies ADD COLUMN IF NOT EXISTS allow_cidrs TEXT[] NOT NULL DEFAULT '{}';
