use std::collections::HashSet;

#[allow(dead_code)]
pub struct LdapSchema {
    pub object_classes: HashSet<String>,
    pub attribute_types: HashSet<String>,
}

impl Default for LdapSchema {
    fn default() -> Self {
        let mut object_classes = HashSet::new();
        let mut attribute_types = HashSet::new();

        // Core schema (RFC 4512)
        object_classes.insert("top".to_string());
        object_classes.insert("person".to_string());
        object_classes.insert("organizationalPerson".to_string());
        object_classes.insert("inetOrgPerson".to_string());
        object_classes.insert("organization".to_string());
        object_classes.insert("organizationalUnit".to_string());
        object_classes.insert("device".to_string());

        // POSIX Account (RFC 2307)
        object_classes.insert("posixAccount".to_string());
        object_classes.insert("shadowAccount".to_string());
        object_classes.insert("posixGroup".to_string());
        object_classes.insert("ipHost".to_string());

        // OATH (OTP) Schema
        object_classes.insert("oathTOTPUser".to_string());
        object_classes.insert("oathHOTPUser".to_string());

        // Sudo Schema
        object_classes.insert("sudoRole".to_string());

        // Tailscale Schema
        object_classes.insert("tailscaleObject".to_string());

        // Core Attributes
        attribute_types.insert("cn".to_string());
        attribute_types.insert("sn".to_string());
        attribute_types.insert("uid".to_string());
        attribute_types.insert("ou".to_string());
        attribute_types.insert("o".to_string());
        attribute_types.insert("dc".to_string());
        attribute_types.insert("objectClass".to_string());
        attribute_types.insert("userPassword".to_string());
        attribute_types.insert("mail".to_string());
        attribute_types.insert("mobile".to_string());
        attribute_types.insert("description".to_string());

        // POSIX Attributes
        attribute_types.insert("uidNumber".to_string());
        attribute_types.insert("gidNumber".to_string());
        attribute_types.insert("homeDirectory".to_string());
        attribute_types.insert("loginShell".to_string());
        attribute_types.insert("gecos".to_string());
        attribute_types.insert("memberUid".to_string());
        attribute_types.insert("ipHostNumber".to_string());

        // Shadow Account Attributes
        attribute_types.insert("shadowLastChange".to_string());
        attribute_types.insert("shadowMin".to_string());
        attribute_types.insert("shadowMax".to_string());
        attribute_types.insert("shadowWarning".to_string());
        attribute_types.insert("shadowInactive".to_string());
        attribute_types.insert("shadowExpire".to_string());
        attribute_types.insert("shadowFlag".to_string());

        // OATH (OTP) Attributes
        attribute_types.insert("oathSecret".to_string());
        attribute_types.insert("oathTokenIdentifier".to_string());
        attribute_types.insert("oathCounter".to_string());
        attribute_types.insert("oathDigits".to_string());
        attribute_types.insert("oathWindow".to_string());
        attribute_types.insert("oathTimeStep".to_string());

        // Sudo Attributes
        attribute_types.insert("sudoCommand".to_string());
        attribute_types.insert("sudoHost".to_string());
        attribute_types.insert("sudoUser".to_string());
        attribute_types.insert("sudoOption".to_string());
        attribute_types.insert("sudoRunAsUser".to_string());
        attribute_types.insert("sudoRunAsGroup".to_string());
        attribute_types.insert("sudoNotBefore".to_string());
        attribute_types.insert("sudoNotAfter".to_string());
        attribute_types.insert("sudoOrder".to_string());

        // Tailscale Attributes
        attribute_types.insert("tsId".to_string());
        attribute_types.insert("tsLoginName".to_string());
        attribute_types.insert("tsDisplayName".to_string());
        attribute_types.insert("tsProfilePicUrl".to_string());
        attribute_types.insert("tsTailnetId".to_string());
        attribute_types.insert("tsRole".to_string());
        attribute_types.insert("tsStatus".to_string());
        attribute_types.insert("tsAddress".to_string());
        attribute_types.insert("tsAllowedIp".to_string());
        attribute_types.insert("tsExtraIp".to_string());
        attribute_types.insert("tsEndpoint".to_string());
        attribute_types.insert("tsDerp".to_string());
        attribute_types.insert("tsClientVersion".to_string());
        attribute_types.insert("tsOs".to_string());
        attribute_types.insert("tsName".to_string());
        attribute_types.insert("tsHostname".to_string());
        attribute_types.insert("tsMachineKey".to_string());
        attribute_types.insert("tsNodeKey".to_string());
        attribute_types.insert("tsCreated".to_string());
        attribute_types.insert("tsLastSeen".to_string());
        attribute_types.insert("tsExpires".to_string());
        attribute_types.insert("tsNeverExpires".to_string());
        attribute_types.insert("tsAuthorized".to_string());
        attribute_types.insert("tsIsExternal".to_string());
        attribute_types.insert("tsUpdateAvailable".to_string());
        attribute_types.insert("tsRouteAll".to_string());
        attribute_types.insert("tsHasSubnet".to_string());

        Self {
            object_classes,
            attribute_types,
        }
    }
}
