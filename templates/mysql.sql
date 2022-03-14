START TRANSACTION;

CREATE TABLE `clients` (
  `id` VARCHAR(255) NOT NULL,
  `private_key` VARCHAR(255) NOT NULL,
  `public_key` VARCHAR(255) NOT NULL,
  `preshared_key` VARCHAR(255) NOT NULL,
  `name` VARCHAR(255) NOT NULL,
  `email` VARCHAR(255),
  `allocated_ips` VARCHAR(2550) NOT NULL,
  `allowed_ips` VARCHAR(2550) NOT NULL,
  `extra_allowed_ips` VARCHAR(2550),
  `use_server_dns` TINYINT(1) NOT NULL,
  `enabled` TINYINT(1) NOT NULL,
  `created_at` DATETIME NOT NULL,
  `updated_at` DATETIME NOT NULL
);

CREATE TABLE `global_settings` (
  `id` INT(11) NOT NULL,
  `endpoint_address` VARCHAR(255) NOT NULL,
  `dns_servers` VARCHAR(2550) NOT NULL,
  `mtu` VARCHAR(255) NOT NULL,
  `persistent_keepalive` VARCHAR(255) NOT NULL,
  `config_file_path` VARCHAR(255) NOT NULL,
  `updated_at` DATETIME NOT NULL
);

CREATE TABLE `interfaces` (
  `id` INT(11) NOT NULL,
  `addresses` VARCHAR(2550) NOT NULL,
  `listen_port` VARCHAR(5) NOT NULL,
  `updated_at` DATETIME NOT NULL,
  `post_up` VARCHAR(255) DEFAULT "",
  `post_down` VARCHAR(255) DEFAULT ""
);

CREATE TABLE `keypair` (
  `id` INT(11) NOT NULL,
  `private_key` VARCHAR(255) NOT NULL,
  `public_key` VARCHAR(255) NOT NULL,
  `updated_at` DATETIME NOT NULL
);

CREATE TABLE `users` (
  `id` INT(11) NOT NULL,
  `username` VARCHAR(255) NOT NULL,
  `password` VARCHAR(255) NOT NULL
);


ALTER TABLE `clients`
  ADD PRIMARY KEY (`id`);

ALTER TABLE `global_settings`
  ADD PRIMARY KEY (`id`);

ALTER TABLE `interfaces`
  ADD PRIMARY KEY (`id`);

ALTER TABLE `keypair`
  ADD PRIMARY KEY (`id`);

ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);


ALTER TABLE `global_settings`
  MODIFY `id` INT(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `interfaces`
  MODIFY `id` INT(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `keypair`
  MODIFY `id` INT(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `users`
  MODIFY `id` INT(11) NOT NULL AUTO_INCREMENT;

COMMIT;