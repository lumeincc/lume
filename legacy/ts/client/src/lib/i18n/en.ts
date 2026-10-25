// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * English catalogue — the source of truth for keys.
 *
 * `TranslationKey` is derived from this object, so a key that does not exist
 * here is a compile error rather than a raw key rendered on screen. Every other
 * locale is checked against this one by `npm run check:i18n`.
 *
 * Keys are namespaced by surface. Flat names collide once the catalogue grows
 * past a couple of screens.
 */
export const en = {
  // Connection status banner
  "status.rateLimited": "Rate limited. Try again in 60 seconds.",
  "status.kicked": "Disconnected — too many active sessions.",
  "status.authError": "WebSocket authentication failed",

  // Error boundary
  "error.title": "Something went wrong",
  "error.body": "An unexpected error occurred.",
  "error.reload": "Reload",

  // Groups
  "group.memberCount": {
    one: "{count} member",
    other: "{count} members",
  },

  // Shared across surfaces
  "common.cancel": "Cancel",

  // Settings — appearance
  "settings.appearance.title": "Appearance",
  "settings.appearance.theme": "Theme",
  "settings.appearance.light": "Light",
  "settings.appearance.dark": "Dark",
  "settings.appearance.system": "System",
  "settings.appearance.language": "Language",

  // Settings — notifications
  "settings.notifications.title": "Notifications",
  "settings.notifications.desktop": "Desktop notifications",
  "settings.notifications.desktopHint": "Show a notification when a new message arrives",
  "settings.notifications.blocked": "Blocked by browser — enable in site settings",
  "settings.notifications.sound": "Sound",
  "settings.notifications.soundHint": "Play a chime when a new message arrives",

  // Settings — danger zone
  "settings.danger.title": "Danger zone",
  "settings.danger.deleteAccount": "Delete account and wipe data",
  "settings.danger.modalTitle": "Delete account",
  "settings.danger.warning":
    "This will permanently erase all local data including keys, contacts, and messages. This action cannot be undone.",
  "settings.danger.pinPlaceholder": "Enter PIN to confirm",
  "settings.danger.invalidPin": "Invalid PIN",
  "settings.danger.verificationFailed": "Verification failed",
  "settings.danger.verifying": "Verifying...",
  "settings.danger.confirm": "Delete everything",

  // Settings — security / PIN
  "settings.security.title": "Security",
  "settings.security.changePin": "Change PIN",
  "settings.security.changing": "Changing…",
  "settings.security.changed": "PIN changed successfully",
  "settings.security.currentPin": "Current PIN",
  "settings.security.newPin": "New PIN",
  "settings.security.confirmNewPinPlaceholder": "Confirm New PIN",
  "settings.security.confirmNewPinLabel": "Confirm new PIN",
  "settings.security.errorTooShort": "New PIN must be at least 8 characters",
  "settings.security.errorMismatch": "PINs do not match",
  "settings.security.errorSameAsCurrent": "New PIN must be different from the current one",
  "settings.security.errorWrongCurrent": "Current PIN is incorrect",

  // Settings — profile
  "settings.profile.title": "Profile",
  "settings.profile.changeAvatar": "Change avatar",
  "settings.profile.displayName": "Display name",
  "settings.profile.displayNamePlaceholder": "Enter display name",
  "settings.profile.saving": "Saving...",
  "settings.profile.saved": "Saved",
  "settings.profile.username": "Username",
  "settings.profile.usernameHidden": "Hidden",
  "settings.profile.errorImageType": "Only PNG, JPEG, and WebP images are supported.",
  "settings.profile.errorImageSize": "Image must be under 2 MB.",
  "settings.profile.errorUpload": "Upload failed.",
  "settings.profile.errorAvatar": "Failed to upload avatar.",
  "settings.profile.errorDisplayName": "Failed to save display name.",

  // Settings — privacy
  "settings.privacy.title": "Privacy",
  "settings.privacy.discoverable": "Discoverable by username",
  "settings.privacy.discoverableHint": "When off, others can only find you via invite link",
  "settings.privacy.inviteHint": "Share this link so others can add you",
  "settings.privacy.generateInvite": "Generate invite link",
  "settings.privacy.generateNew": "Generate new",
  "settings.privacy.generating": "Generating...",
  "settings.privacy.copy": "Copy",
  "settings.privacy.copied": "Copied!",
  "settings.privacy.qrAlt": "Invite QR code",
  "settings.privacy.expiresIn": "Expires in {time}",
  "settings.privacy.expired": "Expired",

  // Settings — hidden chats
  "settings.hidden.toggle": "Hidden chats",
  "settings.hidden.toggleHint": "Enable a separate hidden chat list protected by PIN",
  "settings.hidden.titleSetup": "Hidden Chats PIN",
  "settings.hidden.titleChange": "Change Hidden PIN",
  "settings.hidden.titleReset": "Reset Hidden PIN",
  "settings.hidden.enable": "Enable Hidden Chats",
  "settings.hidden.hintSetup": "Create a separate PIN for opening hidden chats.",
  "settings.hidden.hintChange": "Enter current hidden PIN and set a new one.",
  "settings.hidden.hintReset":
    "Reset hidden PIN using your account PIN and set a new hidden PIN.",
  "settings.hidden.currentPin": "Current hidden PIN",
  "settings.hidden.accountPin": "Account PIN",
  "settings.hidden.newPin": "New hidden PIN",
  "settings.hidden.confirmPin": "Confirm new hidden PIN",
  "settings.hidden.errorTooShort": "PIN must be at least 8 characters",
  "settings.hidden.errorMismatch": "PINs do not match",
  "settings.hidden.errorNotConfigured": "Hidden chats PIN is not configured",
  "settings.hidden.errorEnterCurrent": "Enter current hidden chats PIN",
  "settings.hidden.errorWrongCurrent": "Current hidden chats PIN is incorrect",
  "settings.hidden.errorUnlockRequired": "Unlock session required",
  "settings.hidden.errorWrongAccountPin": "Account PIN is incorrect",
  "settings.hidden.errorUnlockToSave": "Unlock session required to save hidden PIN",
  "settings.hidden.errorSaveFailed": "Failed to save hidden chats PIN",

  // Settings — page shell and panic wipe
  "settings.title": "Settings",
  "settings.backToChats": "Back to chats",
  "settings.back": "Back",
  "settings.wipe.title": "Wipe all data",
  "settings.wipe.warning": "All local data will be permanently erased. This cannot be undone.",
  "settings.wipe.confirm": "Confirm wipe",

  // Auth — shared
  "auth.welcome": "Welcome",
  "auth.welcomeBack": "Welcome back",
  "auth.tagline": "Built with cryptography, not trust.",
  "auth.newAccount": "New account",
  "auth.restoreAccess": "Restore access",
  "auth.stepOf": "Step {n} of 3",
  "auth.haveAccount": "Already have an account?",
  "auth.skip": "Skip",
  "common.delete": "Delete",
  "common.dismiss": "Dismiss",
  "common.saved": "Saved",
  "common.unlock": "Unlock",
  "common.username": "Username",
  "chat.noMessagesYet": "No messages yet",
  "chat.sendFirst": "Send the first message.",
  "chat.sendFirstGroup": "Send the first message to the group.",
  "chat.notFound": "Chat not found",
  "chat.attachmentPreview": "Attachment preview",
  "contact.lumeUser": "LUME user",
  "contact.delete": "Delete contact",
  "contact.startChat": "Start chat",
  "contact.list": "Contacts",
  "profile.edit": "Edit profile",
  "hidden.title": "Hidden chats",
  "hidden.prompt": "Enter your hidden chats PIN to open hidden conversations.",
  "hidden.change": "Change Hidden PIN",
  "hidden.reset": "Reset Hidden PIN",
  "status.secure": "Secure",
  "status.verified": "Verified",
  "status.keyUpdated": "Key updated",
  "status.online": "Online",
  "status.offline": "Offline",
  "group.name": "Group name",
  "settings.pinChanged": "PIN changed.",
  "settings.selfDestructDefault": "Self-destruct default",
  "shortcuts.title": "Keyboard shortcuts",
  "theme.toggle": "Toggle theme",
  "nav.panels": "Panel navigation",
  "nav.profilePanel": "Profile panel",
  "nav.messagesPanel": "Messages panel",
  "auth.setup.errorUsernameShort": "Minimum 3 characters",
  "auth.setup.errorUsernameChars": "Only letters, numbers and underscore",
  "auth.setup.errorUsernameTaken": "Username taken",
  "auth.setup.errorRegistration": "Registration error",
  "settings.danger.enterPin": "Enter your PIN to confirm",
  "settings.backupStale": "Old backups are encrypted with the previous PIN. Create a new backup to use the current PIN.",
  "auth.or": "or",
  "auth.continue": "Continue",
  "auth.login": "Log in",
  "auth.createAccount": "Create account",
  "auth.recoverWithPhrase": "Recover with phrase",
  "auth.usernameLabel": "Username",
  "auth.usernamePlaceholder": "username",
  "auth.back": "Back",
  "auth.repeatPin": "Repeat PIN",

  // Auth — unlock
  "auth.unlock.title": "Welcome back",
  // Idle lock
  "lock.warningTitle": "Locking soon",
  "lock.warningBody": "No activity — locking in {seconds}s",
  "lock.stayUnlocked": "Stay unlocked",

  "auth.unlock.pinLabel": "PIN",
  "auth.unlock.pinAria": "Enter PIN",
  "auth.unlock.checking": "Checking…",
  "auth.unlock.newHere": "New here?",
  "auth.unlock.errorTooManyAttempts": "Too many attempts",
  "auth.unlock.errorInvalidPin": "Invalid PIN",
  "auth.unlock.errorIdentityMismatch":
    "This username belongs to a different identity on the server.",
  "auth.unlock.errorUnreachable": "Could not reach server. Try again or recover with phrase.",
  "auth.unlock.errorProfileMissing": "Profile missing. Recover account with phrase.",
  "auth.unlock.errorGeneric": "Unlock error",

  // Auth — setup
  "auth.setup.title": "Create your account",
  "auth.setup.pinTitle": "Set a PIN",
  "auth.setup.creating": "Creating account…",
  "auth.setup.recoveryTitle": "Save your recovery key",
  "auth.setup.recoveryHint": "Without it, account recovery is impossible.",
  "auth.setup.download": "Download",
  "auth.setup.downloadAria": "Download recovery phrase as text file",
  "auth.setup.copy": "Copy",
  "auth.setup.copied": "Copied",
  "auth.setup.copyAria": "Copy recovery phrase to clipboard",
  "auth.setup.saved": "I saved it",
  "auth.setup.created": "Account created",
  "auth.setup.errorPinFormat": "Enter a PIN of at least 8 characters",
  "auth.setup.errorPinMismatch": "PINs do not match",

  // Auth — recover
  "auth.recover.title": "Restore access",
  "auth.recover.phraseLabel": "Recovery phrase",
  "auth.recover.phrasePlaceholder": "Enter your words",
  "auth.recover.newPin": "New PIN",
  "auth.recover.recovering": "Recovering…",
  "auth.recover.errorUsername": "Enter a valid username",
  "auth.recover.errorWordCount": "Phrase must contain 12 or 24 words",
  "auth.recover.errorInvalidPhrase": "Invalid recovery phrase",
  "auth.recover.errorPinTooShort": "PIN must be at least 8 chars",
  "auth.recover.errorPinMismatch": "PINs do not match",
  "auth.recover.errorUnreachable": "Could not reach server. Try again later.",
  "auth.recover.errorNoMatch": "Recovery phrase does not match this username",
  "auth.recover.errorGeneric": "Recovery error",

  // Invite
  "invite.title": "Invite link",
  "invite.addContact": "Add contact",
  "invite.wantsToConnect": "wants to connect with you",
  "invite.adding": "Adding…",
  "invite.addAndChat": "Add contact & chat",
  "invite.added": "Contact added",
  "invite.addedHint": "You’re connected. Say hello.",
  "invite.openChat": "Open chat",
  "invite.goToChats": "Go to chats",
  "invite.errorInvalid": "Invalid invite link",
  "invite.errorSelf": "Cannot add yourself",
  "invite.errorFailed": "Failed to add contact",

  // Chat list
  "chatList.tabChats": "Chats",
  "chatList.tabGroups": "Groups",
  "chatList.searchChats": "Search",
  "chatList.searchGroups": "Search groups",
  "chatList.searchChatsAria": "Search chats",
  "chatList.searchGroupsAria": "Search groups",
  "chatList.noChats": "No chats yet",
  "chatList.noGroups": "No groups yet",
  "chatList.blocked": "Blocked",
  "chatList.startMessaging": "Start messaging",
  "chatList.hideChat": "Hide chat",
  "chatList.unhideChat": "Unhide chat",
  "chatList.newChat": "New chat",
  "chatList.newGroup": "New group",
  "chatList.settings": "Settings",
  "chatList.openHidden": "Open hidden chats",
  "chatList.backToMain": "Back to main chats",
  "chatList.mainChats": "Main chats",
  "chatList.hiddenChats": "Hidden chats",
  "chatList.hiddenPinPlaceholder": "Hidden chats PIN",
  "chatList.errorHiddenPin": "Invalid hidden chats PIN",

  // Left rail
  "rail.profile": "Your profile",
  "rail.messenger": "Messenger",
  "rail.settings": "Settings",
  "rail.files": "Files",
  "rail.filesComingSoon": "Files (coming soon)",
  "rail.backup": "Backup",
  "rail.wipe": "Wipe local data",
  "rail.online": "Online",
  "rail.connecting": "Connecting…",
  "rail.offline": "Offline",
  "rail.anonymous": "Anonymous",
  "rail.guest": "Guest",

  // Modals — add contact
  "modal.addContact.usernamePlaceholder": "@username",
  "modal.addContact.usernameAria": "Recipient username",
  "modal.addContact.starting": "Starting…",
  "modal.addContact.start": "Start chat",

  // Modals — panic wipe
  "modal.panic.title": "Wipe data?",
  "modal.panic.warning":
    "This will delete all local keys, contacts and messages on this device. It cannot be undone.",
  "modal.panic.confirm": "Wipe",

  // Modals — own profile
  "modal.profile.title": "Your profile",
  "modal.profile.online": "Online",
  "modal.profile.offline": "Offline",
  "modal.profile.discoverable": "Discoverable",
  "modal.profile.visible": "Visible to others",
  "modal.profile.hidden": "Hidden",

  // Modals — group membership
  "modal.group.addMemberTitle": "Add member",
  "modal.group.addMember": "Add member",
  "modal.group.createTitle": "New group",
  "modal.group.create": "Create group",
  "modal.group.namePlaceholder": "Enter group name",
  "modal.group.membersLabel": "Members ({selected}/{max})",
  "modal.group.searchContacts": "Search contacts...",
  "modal.group.searchContactsAria": "Search contacts",
  "modal.group.noContactsToAdd": "No contacts available to add",
  "modal.group.noContacts": "No contacts yet",
  "modal.group.noMatches": "No matches",
  "modal.group.errorSelectContact": "Select a contact to add",
  "modal.group.errorNameRequired": "Group name is required",
  "modal.group.errorSelectMember": "Select at least 1 member",
  "modal.group.errorAuth": "Authentication required",

  // Modals — backup
  "modal.backup.title": "Backup & restore",
  "modal.backup.hint":
    "Export keys/chats/contacts as an encrypted file. Enter your PIN to encrypt/decrypt. Store offline.",
  "modal.backup.pinPlaceholder": "Enter PIN",
  "modal.backup.pinAria": "Backup PIN",
  "modal.backup.export": "Export",
  "modal.backup.restore": "Restore",
  "modal.backup.selectFile": "Select backup file",
  "modal.backup.selectFileAria": "Select backup file",
  "modal.backup.enterPinExport": "Enter your PIN to export backup.",
  "modal.backup.enterPinRestore": "Enter your PIN to restore backup.",
  "modal.backup.exportFailed": "Backup failed. Check your PIN and try again.",
  "modal.backup.restored": "Backup restored. Restart the application.",
  "modal.backup.restoreFailed": "Restore failed. Check your file and PIN.",

  // Chat — header
  "chat.back": "Back",
  "chat.options": "Options",

  // Chat — composer
  "chat.messagePlaceholder": "Message @{username}",
  "chat.messagePlaceholderPlain": "Message",
  "chat.messageInputAria": "Message input",
  "chat.attachFile": "Attach file",
  "chat.removeAttachment": "Remove attachment",
  "chat.cancelReply": "Cancel reply",
  "chat.selfDestructTimer": "Self-destruct timer",
  "chat.autoDelete": "Auto-delete: {timer}",
  "chat.send": "Send",
  "chat.replyToYou": "You",
  "chat.replyToUnknown": "Unknown",

  // Chat — contact profile
  "chat.profile.title": "Contact profile",
  "chat.profile.safetyNumber": "Safety number",
  "chat.profile.safetyHint":
    "Compare this number with your contact out of band. If it matches, mark verified.",
  "chat.profile.copy": "Copy",
  "chat.profile.copied": "Copied",
  "chat.profile.verified": "Verified",
  "chat.profile.markVerified": "Mark verified",
  "chat.profile.processing": "Processing…",
  "chat.profile.block": "Block contact",
  "chat.profile.unblock": "Unblock contact",
  "chat.profile.hideChat": "Hide chat",
  "chat.profile.unhideChat": "Unhide chat",

  // Chat — message bubble
  "chat.message.reply": "Reply",
  "chat.message.delete": "Delete message",
  "chat.message.failedToLoad": "Failed to load",
  "chat.message.retry": "Retry",
  "chat.message.downloadFailed": "Download failed — tap to retry",

  // Groups — view
  "group.backToGroups": "Back to groups",
  "group.info": "Group info",
  "group.backToChat": "Back to chat",
  "group.messageInputAria": "Group message input",
  "group.addMembersToChat": "Add members to start chatting",
  "group.addMember": "Add member",
  "group.membersHeading": "Members",
  "group.infoHeading": "Info",
  "group.created": "Created",
  "group.admin": "Admin",
  "group.removeMember": "Remove {username}",
  "group.leave": "Leave group",
  "group.fileTooLarge": "File too large. Max size: {size}",

  // Groups — typing indicator
  "group.typingOne": "@{name} is typing…",
  "group.typingTwo": "@{first} and @{second} are typing…",
  "group.typingMany": "Several people are typing…",

  // Chat — crypto banner
  "chat.crypto.noSecureSession": "Cannot establish secure session with this contact.",
  "chat.selectAChat": "Select a chat",
  "chat.crypto.storageUnreadable":
    "Local data could not be read. Saving is disabled so nothing is overwritten — do not reinstall or clear site data.",
} as const;

export type TranslationKey = keyof typeof en;
