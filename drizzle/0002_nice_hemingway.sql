ALTER TABLE `users` ADD `twoFactorEnrollmentId` varchar(64);
--> statement-breakpoint
ALTER TABLE `users` ADD `recoveryCodesHash` text;
