START TRANSACTION;

CREATE TABLE `allocated_ips` (
  `id` int(11) NOT NULL,
  `ip` varchar(255) NOT NULL,
  `client` varchar(255) NOT NULL
);

CREATE TABLE `allowed_ips` (
  `id` int(11) NOT NULL,
  `ip` varchar(255) NOT NULL,
  `client` varchar(255) NOT NULL
);

CREATE TABLE `clients` (
  `id` varchar(255) NOT NULL,
  `private_key` varchar(255) NOT NULL,
  `public_key` varchar(255) NOT NULL,
  `preshared_key` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `use_server_dns` tinyint(1) NOT NULL,
  `enabled` tinyint(1) NOT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  `email` varchar(255)
);

CREATE TABLE `dns_servers` (
  `id` int(11) NOT NULL,
  `ip` varchar(255) NOT NULL,
  `config` int(11) NOT NULL
);

CREATE TABLE `extra_allowed_ips` (
  `id` int(11) NOT NULL,
  `ip` varchar(255) NOT NULL,
  `client` varchar(255) NOT NULL
);

CREATE TABLE `global_settings` (
  `id` int(11) NOT NULL,
  `endpoint_address` varchar(255) NOT NULL,
  `mtu` varchar(255) NOT NULL,
  `persistent_keepalive` varchar(255) NOT NULL,
  `config_file_path` varchar(255) NOT NULL,
  `updated_at` datetime NOT NULL
);

CREATE TABLE `interfaces` (
  `id` int(11) NOT NULL,
  `listen_port` varchar(5) NOT NULL,
  `updated_at` datetime NOT NULL,
  `post_up` varchar(255) DEFAULT "",
  `post_down` varchar(255) DEFAULT ""
);

CREATE TABLE `interface_addresses` (
  `id` int(11) NOT NULL,
  `ip` varchar(255) NOT NULL,
  `interface` int(11) NOT NULL
);

CREATE TABLE `keypair` (
  `id` int(11) NOT NULL,
  `private_key` varchar(255) NOT NULL,
  `public_key` varchar(255) NOT NULL,
  `updated_at` datetime NOT NULL
);

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL
);


ALTER TABLE `allocated_ips`
  ADD PRIMARY KEY (`id`),
  ADD KEY `client` (`client`);

ALTER TABLE `allowed_ips`
  ADD PRIMARY KEY (`id`),
  ADD KEY `client` (`client`);

ALTER TABLE `clients`
  ADD PRIMARY KEY (`id`);

ALTER TABLE `dns_servers`
  ADD PRIMARY KEY (`id`),
  ADD KEY `config` (`config`);

ALTER TABLE `extra_allowed_ips`
  ADD PRIMARY KEY (`id`),
  ADD KEY `client` (`client`);

ALTER TABLE `global_settings`
  ADD PRIMARY KEY (`id`);

ALTER TABLE `interfaces`
  ADD PRIMARY KEY (`id`);

ALTER TABLE `interface_addresses`
  ADD PRIMARY KEY (`id`),
  ADD KEY `interface` (`interface`);

ALTER TABLE `keypair`
  ADD PRIMARY KEY (`id`);

ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);


ALTER TABLE `allocated_ips`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `allowed_ips`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `dns_servers`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `extra_allowed_ips`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `global_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `interfaces`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `interface_addresses`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `keypair`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;


ALTER TABLE `allocated_ips`
  ADD CONSTRAINT `allocated_ips_ibfk_1` FOREIGN KEY (`client`) REFERENCES `clients` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `allowed_ips`
  ADD CONSTRAINT `allowed_ips_ibfk_1` FOREIGN KEY (`client`) REFERENCES `clients` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `dns_servers`
  ADD CONSTRAINT `dns_servers_ibfk_1` FOREIGN KEY (`config`) REFERENCES `global_settings` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `extra_allowed_ips`
  ADD CONSTRAINT `extra_allowed_ips_ibfk_1` FOREIGN KEY (`client`) REFERENCES `clients` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `interface_addresses`
  ADD CONSTRAINT `interface_addresses_ibfk_1` FOREIGN KEY (`interface`) REFERENCES `interfaces` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;
COMMIT;