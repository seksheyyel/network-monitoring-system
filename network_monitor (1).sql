-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 20, 2026 at 04:53 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `network_monitor`
--

-- --------------------------------------------------------

--
-- Table structure for table `activity_logs`
--

CREATE TABLE `activity_logs` (
  `id` int(10) UNSIGNED NOT NULL,
  `user_id` int(10) UNSIGNED DEFAULT NULL,
  `username` varchar(100) NOT NULL DEFAULT '',
  `action` varchar(120) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `status` enum('success','warning','failed') NOT NULL DEFAULT 'success',
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `activity_logs`
--

INSERT INTO `activity_logs` (`id`, `user_id`, `username`, `action`, `ip_address`, `status`, `created_at`) VALUES
(1, 1, 'admin', 'Login', '192.168.1.10', 'success', '2026-05-10 21:29:24'),
(2, 1, 'admin', 'Delete Alert', '192.168.1.10', 'warning', '2026-05-10 21:30:24'),
(3, 1, 'admin', 'Delete All Alerts', '192.168.1.10', 'warning', '2026-05-10 21:31:24'),
(4, 1, 'admin', 'Logout', '192.168.1.10', 'success', '2026-05-10 21:32:24'),
(5, NULL, 'hacker', 'Login', '203.0.113.99', 'failed', '2026-05-10 21:33:24'),
(6, NULL, 'root', 'Login', '198.51.100.42', 'failed', '2026-05-10 21:34:24'),
(7, NULL, 'admin', 'Delete All Alerts', '127.0.0.1', 'warning', '2026-05-10 21:36:53'),
(8, NULL, 'admin', 'Logout', '127.0.0.1', 'success', '2026-05-10 21:44:16'),
(9, NULL, 'admin', 'Login', '127.0.0.1', 'failed', '2026-05-10 21:44:21'),
(10, NULL, 'admin', 'Login', '127.0.0.1', 'failed', '2026-05-10 21:44:24'),
(11, 1, 'admin', 'Login', '127.0.0.1', 'success', '2026-05-10 21:44:28'),
(12, 1, 'admin', 'Delete Alert', '127.0.0.1', 'warning', '2026-05-10 21:47:03'),
(13, 1, 'admin', 'Delete All Alerts', '127.0.0.1', 'warning', '2026-05-10 21:47:16'),
(14, 1, 'admin', 'Logout', '127.0.0.1', 'success', '2026-05-10 21:48:33'),
(15, 2, 'bautista', 'Login', '127.0.0.1', 'success', '2026-05-10 21:48:40'),
(16, 2, 'bautista', 'Delete All Alerts', '127.0.0.1', 'warning', '2026-05-10 21:49:58'),
(17, NULL, 'bautista', 'Login', '127.0.0.1', 'failed', '2026-05-14 22:24:04'),
(18, NULL, 'bautista', 'Login', '127.0.0.1', 'failed', '2026-05-14 22:24:13'),
(19, 1, 'admin', 'Login', '127.0.0.1', 'success', '2026-05-14 22:24:18'),
(20, 1, 'admin', 'Delete All Alerts', '127.0.0.1', 'warning', '2026-05-14 22:25:58'),
(21, 1, 'admin', 'Update ARP Thresholds', '127.0.0.1', 'success', '2026-05-14 22:59:45'),
(22, 1, 'admin', 'Update ARP Thresholds', '127.0.0.1', 'success', '2026-05-14 22:59:55'),
(23, 1, 'admin', 'Update DDOS Thresholds', '127.0.0.1', 'success', '2026-05-14 23:00:16'),
(24, 1, 'admin', 'Login', '127.0.0.1', 'success', '2026-05-14 23:09:02'),
(25, 1, 'admin', 'Update DDOS Thresholds', '127.0.0.1', 'success', '2026-05-14 23:09:18'),
(26, 1, 'admin', 'Update DDOS Thresholds', '127.0.0.1', 'success', '2026-05-14 23:10:38'),
(27, 1, 'admin', 'Logout', '127.0.0.1', 'success', '2026-05-14 23:31:54'),
(28, NULL, 'admin', 'Login', '127.0.0.1', 'failed', '2026-05-14 23:31:58'),
(29, NULL, 'admin', 'Login', '127.0.0.1', 'failed', '2026-05-14 23:32:00'),
(30, 1, 'admin', 'Login', '127.0.0.1', 'success', '2026-05-14 23:32:03'),
(31, 1, 'admin', 'Update DDOS Thresholds', '127.0.0.1', 'success', '2026-05-14 23:32:19'),
(32, 1, 'admin', 'Logout', '127.0.0.1', 'success', '2026-05-14 23:32:23'),
(33, 1, 'admin', 'Login', '127.0.0.1', 'success', '2026-05-14 23:32:26'),
(34, 1, 'admin', 'Login', '127.0.0.1', 'success', '2026-05-14 23:34:00'),
(35, 1, 'admin', 'Login', '127.0.0.1', 'success', '2026-05-20 22:03:25'),
(36, NULL, 'admin1', 'Login', '127.0.0.1', 'failed', '2026-05-20 22:11:02'),
(37, 1, 'admin', 'Login', '127.0.0.1', 'success', '2026-05-20 22:11:06'),
(38, 1, 'admin', 'Logout', '127.0.0.1', 'success', '2026-05-20 22:18:31'),
(39, 1, 'admin', 'Login', '127.0.0.1', 'success', '2026-05-20 22:18:46'),
(40, 1, 'admin', 'Login', '127.0.0.1', 'success', '2026-05-20 22:20:47'),
(41, 1, 'admin', 'Update DDOS Thresholds', '127.0.0.1', 'success', '2026-05-20 22:33:34'),
(42, 1, 'admin', 'Delete All Alerts', '127.0.0.1', 'warning', '2026-05-20 22:33:47'),
(43, 1, 'admin', 'Login', '127.0.0.1', 'success', '2026-05-20 22:46:27');

-- --------------------------------------------------------

--
-- Table structure for table `admin`
--

CREATE TABLE `admin` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `admin`
--

INSERT INTO `admin` (`id`, `username`, `password`) VALUES
(1, 'admin', '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9'),
(2, 'bautista', '41e5653fc7aeb894026d6bb7b2db7f65902b454945fa8fd65a6327047b5277fb');

-- --------------------------------------------------------

--
-- Table structure for table `network_alerts`
--

CREATE TABLE `network_alerts` (
  `id` int(11) NOT NULL,
  `alert_type` varchar(50) NOT NULL,
  `source_ip` varchar(45) NOT NULL,
  `details` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`details`)),
  `timestamp` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `settings`
--

CREATE TABLE `settings` (
  `key_name` varchar(50) NOT NULL,
  `value` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `settings`
--

INSERT INTO `settings` (`key_name`, `value`) VALUES
('arp_cooldown', 15),
('arp_threshold', 3),
('arp_window', 30),
('ddos_cooldown', 15),
('ddos_threshold', 5000),
('ddos_window', 3),
('portscan_cooldown', 30),
('portscan_threshold', 20),
('portscan_window', 10);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `activity_logs`
--
ALTER TABLE `activity_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_username` (`username`),
  ADD KEY `idx_action` (`action`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_created_at` (`created_at`);

--
-- Indexes for table `admin`
--
ALTER TABLE `admin`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Indexes for table `network_alerts`
--
ALTER TABLE `network_alerts`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `settings`
--
ALTER TABLE `settings`
  ADD PRIMARY KEY (`key_name`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `activity_logs`
--
ALTER TABLE `activity_logs`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=44;

--
-- AUTO_INCREMENT for table `admin`
--
ALTER TABLE `admin`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `network_alerts`
--
ALTER TABLE `network_alerts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=129;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
