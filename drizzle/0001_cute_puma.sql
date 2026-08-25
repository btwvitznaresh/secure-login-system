CREATE TABLE `auth_sessions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`tokenHash` varchar(64) NOT NULL,
	`expiresAt` timestamp NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `auth_sessions_id` PRIMARY KEY(`id`),
	CONSTRAINT `auth_sessions_tokenHash_unique` UNIQUE(`tokenHash`)
);
--> statement-breakpoint
ALTER TABLE `users` ADD `passwordHash` varchar(255);--> statement-breakpoint
ALTER TABLE `users` ADD `twoFactorEnabled` int DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `users` ADD `twoFactorSecret` varchar(255);--> statement-breakpoint
ALTER TABLE `users` ADD `recoveryCodesHash` text;