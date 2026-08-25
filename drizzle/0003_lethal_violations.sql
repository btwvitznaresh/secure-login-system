ALTER TABLE `users` ADD `emailVerified` int DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `users` ADD `emailVerificationTokenHash` varchar(64);--> statement-breakpoint
ALTER TABLE `users` ADD `emailVerificationExpiresAt` timestamp;--> statement-breakpoint
ALTER TABLE `users` ADD `passwordResetTokenHash` varchar(64);--> statement-breakpoint
ALTER TABLE `users` ADD `passwordResetExpiresAt` timestamp;