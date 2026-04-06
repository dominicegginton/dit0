use ldap3_proto::proto::LdapPartialAttribute;

/// Private enterprise number arc for dit0 custom schema.
/// Using 1.3.6.1.4.1.99999 as a placeholder PEN prefix.
const DIT0_OID_BASE: &str = "1.3.6.1.4.1.99999";

// ── LDAP Syntaxes (RFC 4517) ────────────────────────────────────────────────

/// Returns the `ldapSyntaxes` values as defined in RFC 4517 §3.3.
pub fn ldap_syntaxes() -> Vec<String> {
    vec![
        "( 1.3.6.1.4.1.1466.115.121.1.3 DESC 'Attribute Type Description' )".into(),
        "( 1.3.6.1.4.1.1466.115.121.1.5 DESC 'Binary' )".into(),
        "( 1.3.6.1.4.1.1466.115.121.1.6 DESC 'Bit String' )".into(),
        "( 1.3.6.1.4.1.1466.115.121.1.7 DESC 'Boolean' )".into(),
        "( 1.3.6.1.4.1.1466.115.121.1.11 DESC 'Country String' )".into(),
        "( 1.3.6.1.4.1.1466.115.121.1.12 DESC 'DN' )".into(),
        "( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )".into(),
        "( 1.3.6.1.4.1.1466.115.121.1.22 DESC 'Facsimile Telephone Number' )".into(),
        "( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'Generalized Time' )".into(),
        "( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5 String' )".into(),
        "( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'INTEGER' )".into(),
        "( 1.3.6.1.4.1.1466.115.121.1.36 DESC 'Numeric String' )".into(),
        "( 1.3.6.1.4.1.1466.115.121.1.37 DESC 'Object Class Description' )".into(),
        "( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )".into(),
        "( 1.3.6.1.4.1.1466.115.121.1.40 DESC 'Octet String' )".into(),
        "( 1.3.6.1.4.1.1466.115.121.1.44 DESC 'Printable String' )".into(),
        "( 1.3.6.1.4.1.1466.115.121.1.50 DESC 'Telephone Number' )".into(),
    ]
}

// ── Matching Rules (RFC 4517 §4) ────────────────────────────────────────────

/// Returns the `matchingRules` values advertised in the subschema.
pub fn matching_rules() -> Vec<String> {
    vec![
        "( 2.5.13.0 NAME 'objectIdentifierMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )".into(),
        "( 2.5.13.1 NAME 'distinguishedNameMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )".into(),
        "( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".into(),
        "( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".into(),
        "( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".into(),
        "( 2.5.13.5 NAME 'caseExactMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".into(),
        "( 2.5.13.6 NAME 'caseExactOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".into(),
        "( 2.5.13.7 NAME 'caseExactSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".into(),
        "( 2.5.13.8 NAME 'numericStringMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )".into(),
        "( 2.5.13.11 NAME 'caseIgnoreListMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".into(),
        "( 2.5.13.14 NAME 'integerMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )".into(),
        "( 2.5.13.16 NAME 'bitStringMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )".into(),
        "( 2.5.13.17 NAME 'octetStringMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )".into(),
        "( 2.5.13.20 NAME 'telephoneNumberMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )".into(),
        "( 2.5.13.27 NAME 'generalizedTimeMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )".into(),
        "( 2.5.13.28 NAME 'generalizedTimeOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )".into(),
        "( 2.5.13.29 NAME 'integerFirstComponentMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )".into(),
        "( 2.5.13.30 NAME 'objectIdentifierFirstComponentMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )".into(),
        "( 1.3.6.1.4.1.1466.109.114.1 NAME 'caseExactIA5Match' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )".into(),
        "( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )".into(),
        "( 1.3.6.1.4.1.1466.109.114.3 NAME 'caseIgnoreIA5SubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )".into(),
    ]
}

/// Returns the `matchingRuleUse` values.
pub fn matching_rule_use() -> Vec<String> {
    vec![
        "( 2.5.13.2 NAME 'caseIgnoreMatch' APPLIES ( cn $ sn $ ou $ o $ description $ gecos $ displayName $ givenName ) )".into(),
        "( 2.5.13.14 NAME 'integerMatch' APPLIES ( uidNumber $ gidNumber ) )".into(),
        "( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' APPLIES ( uid $ mail $ dc $ memberUid ) )".into(),
    ]
}

// ── Attribute Types ─────────────────────────────────────────────────────────

/// Returns the full RFC 4512 §4.1.2 `attributeTypes` definitions.
pub fn attribute_types() -> Vec<String> {
    let mut v = Vec::new();

    // ── Core / RFC 4519 ──
    v.push("( 2.5.4.41 NAME 'name' DESC 'RFC 4519: common supertype of name attributes' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".into());
    v.push("( 2.5.4.3 NAME 'cn' DESC 'RFC 4519: common name' SUP name )".into());
    v.push("( 2.5.4.4 NAME 'sn' DESC 'RFC 4519: surname' SUP name )".into());
    v.push("( 2.5.4.42 NAME 'givenName' DESC 'RFC 4519: given name' SUP name )".into());
    v.push("( 2.5.4.0 NAME 'objectClass' DESC 'RFC 4512: object class of entry' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )".into());
    v.push("( 2.5.4.35 NAME 'userPassword' DESC 'RFC 4519: user password' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )".into());
    v.push("( 0.9.2342.19200300.100.1.25 NAME 'dc' DESC 'RFC 4519: domain component' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )".into());
    v.push("( 0.9.2342.19200300.100.1.1 NAME 'uid' DESC 'RFC 4519: user id' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".into());
    v.push("( 2.5.4.13 NAME 'description' DESC 'RFC 4519: description' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".into());
    v.push("( 2.5.4.10 NAME 'o' DESC 'RFC 4519: organization name' SUP name )".into());
    v.push("( 2.5.4.11 NAME 'ou' DESC 'RFC 4519: organizational unit' SUP name )".into());
    v.push("( 2.5.4.34 NAME 'seeAlso' DESC 'RFC 4519: DN of related object' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )".into());

    // ── inetOrgPerson (RFC 2798) ──
    v.push("( 0.9.2342.19200300.100.1.3 NAME 'mail' DESC 'RFC 1274: RFC822 mailbox' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )".into());
    v.push("( 0.9.2342.19200300.100.1.41 NAME 'mobile' DESC 'RFC 1274: mobile telephone number' EQUALITY telephoneNumberMatch SUBSTR telephoneNumberSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )".into());
    v.push("( 2.16.840.1.113730.3.1.241 NAME 'displayName' DESC 'RFC 2798: preferred name for display' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )".into());

    // ── NIS / RFC 2307bis POSIX attributes ──
    v.push("( 1.3.6.1.1.1.1.0 NAME 'uidNumber' DESC 'RFC 2307: numeric user id' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )".into());
    v.push("( 1.3.6.1.1.1.1.1 NAME 'gidNumber' DESC 'RFC 2307: numeric group id' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )".into());
    v.push("( 1.3.6.1.1.1.1.2 NAME 'gecos' DESC 'RFC 2307: GECOS field' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )".into());
    v.push("( 1.3.6.1.1.1.1.3 NAME 'homeDirectory' DESC 'RFC 2307: home directory' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )".into());
    v.push("( 1.3.6.1.1.1.1.4 NAME 'loginShell' DESC 'RFC 2307: login shell' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )".into());
    v.push("( 1.3.6.1.1.1.1.12 NAME 'memberUid' DESC 'RFC 2307: member uid' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )".into());
    v.push("( 1.3.6.1.1.1.1.6 NAME 'ipHostNumber' DESC 'RFC 2307: IP address' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )".into());

    // ── Shadow account attributes (RFC 2307) ──
    v.push("( 1.3.6.1.1.1.1.5 NAME 'shadowLastChange' DESC 'RFC 2307: days since epoch of last password change' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )".into());
    v.push("( 1.3.6.1.1.1.1.7 NAME 'shadowMin' DESC 'RFC 2307: minimum days between password changes' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )".into());
    v.push("( 1.3.6.1.1.1.1.8 NAME 'shadowMax' DESC 'RFC 2307: maximum days between password changes' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )".into());
    v.push("( 1.3.6.1.1.1.1.9 NAME 'shadowWarning' DESC 'RFC 2307: days before expiry to warn user' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )".into());
    v.push("( 1.3.6.1.1.1.1.10 NAME 'shadowInactive' DESC 'RFC 2307: days after expiry until account disabled' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )".into());
    v.push("( 1.3.6.1.1.1.1.11 NAME 'shadowExpire' DESC 'RFC 2307: days since epoch account expires' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )".into());
    v.push("( 1.3.6.1.1.1.1.13 NAME 'shadowFlag' DESC 'RFC 2307: shadow flag' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )".into());

    // ── Operational attributes (RFC 4512 §3.4) ──
    v.push("( 2.5.18.10 NAME 'subschemaSubentry' DESC 'RFC 4512: subschema subentry DN' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )".into());
    v.push("( 2.5.21.6 NAME 'objectClasses' DESC 'RFC 4512: object classes in subschema' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.37 USAGE directoryOperation )".into());
    v.push("( 2.5.21.5 NAME 'attributeTypes' DESC 'RFC 4512: attribute types in subschema' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.3 USAGE directoryOperation )".into());
    v.push("( 2.5.21.8 NAME 'matchingRules' DESC 'RFC 4512: matching rules in subschema' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.30 USAGE directoryOperation )".into());
    v.push("( 2.5.21.9 NAME 'matchingRuleUse' DESC 'RFC 4512: matching rule uses in subschema' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.31 USAGE directoryOperation )".into());
    v.push("( 1.3.6.1.4.1.1466.101.120.16 NAME 'ldapSyntaxes' DESC 'RFC 4512: LDAP syntaxes' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.54 USAGE directoryOperation )".into());
    v.push("( 2.5.18.1 NAME 'createTimestamp' DESC 'RFC 4512: entry creation time' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )".into());
    v.push("( 2.5.18.2 NAME 'modifyTimestamp' DESC 'RFC 4512: entry modification time' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )".into());
    v.push("( 1.3.6.1.4.1.1466.101.120.6 NAME 'altServer' DESC 'RFC 4512: alternative servers' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 USAGE dSAOperation )".into());
    v.push("( 1.3.6.1.4.1.1466.101.120.5 NAME 'namingContexts' DESC 'RFC 4512: naming contexts' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 USAGE dSAOperation )".into());
    v.push("( 1.3.6.1.4.1.1466.101.120.13 NAME 'supportedControl' DESC 'RFC 4512: supported controls' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )".into());
    v.push("( 1.3.6.1.4.1.1466.101.120.7 NAME 'supportedExtension' DESC 'RFC 4512: supported extended operations' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )".into());
    v.push("( 1.3.6.1.4.1.1466.101.120.15 NAME 'supportedLDAPVersion' DESC 'RFC 4512: supported LDAP versions' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 USAGE dSAOperation )".into());
    v.push("( 1.3.6.1.4.1.1466.101.120.14 NAME 'supportedSASLMechanisms' DESC 'RFC 4512: supported SASL mechanisms' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE dSAOperation )".into());
    v.push("( 1.3.6.1.4.1.4203.1.3.5 NAME 'supportedFeatures' DESC 'RFC 4512: supported features' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )".into());
    v.push("( 2.16.840.1.113730.3.1.36 NAME 'vendorName' DESC 'RFC 3045: vendor name' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )".into());
    v.push("( 2.16.840.1.113730.3.1.37 NAME 'vendorVersion' DESC 'RFC 3045: vendor version' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )".into());

    // ── OATH (OTP) attributes (custom OIDs) ──
    let oath_base = format!("{}.1", DIT0_OID_BASE);
    v.push(format!("( {}.1 NAME 'oathSecret' DESC 'OATH shared secret' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )", oath_base));
    v.push(format!("( {}.2 NAME 'oathTokenIdentifier' DESC 'OATH token identifier' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )", oath_base));
    v.push(format!("( {}.3 NAME 'oathCounter' DESC 'OATH HOTP counter' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )", oath_base));
    v.push(format!("( {}.4 NAME 'oathDigits' DESC 'OATH number of digits' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )", oath_base));
    v.push(format!("( {}.5 NAME 'oathWindow' DESC 'OATH look-ahead window' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )", oath_base));
    v.push(format!("( {}.6 NAME 'oathTimeStep' DESC 'OATH TOTP time step in seconds' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )", oath_base));

    // ── Sudo attributes (1.3.6.1.4.1.15953.9.1.*) ──
    v.push("( 1.3.6.1.4.1.15953.9.1.1 NAME 'sudoUser' DESC 'sudo user or group' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )".into());
    v.push("( 1.3.6.1.4.1.15953.9.1.2 NAME 'sudoHost' DESC 'sudo host' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )".into());
    v.push("( 1.3.6.1.4.1.15953.9.1.3 NAME 'sudoCommand' DESC 'sudo command' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )".into());
    v.push("( 1.3.6.1.4.1.15953.9.1.4 NAME 'sudoRunAsUser' DESC 'sudo run-as user' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )".into());
    v.push("( 1.3.6.1.4.1.15953.9.1.5 NAME 'sudoRunAsGroup' DESC 'sudo run-as group' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )".into());
    v.push("( 1.3.6.1.4.1.15953.9.1.6 NAME 'sudoOption' DESC 'sudo option' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )".into());
    v.push("( 1.3.6.1.4.1.15953.9.1.7 NAME 'sudoOrder' DESC 'sudo order' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )".into());
    v.push("( 1.3.6.1.4.1.15953.9.1.8 NAME 'sudoNotBefore' DESC 'sudo not valid before' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )".into());
    v.push("( 1.3.6.1.4.1.15953.9.1.9 NAME 'sudoNotAfter' DESC 'sudo not valid after' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )".into());

    // ── Tailscale custom attributes ──
    let ts_base = format!("{}.2", DIT0_OID_BASE);
    let ts_attrs = [
        ("1", "tsId", "Tailscale user/device ID"),
        ("2", "tsLoginName", "Tailscale login name"),
        ("3", "tsDisplayName", "Tailscale display name"),
        ("4", "tsProfilePicUrl", "Tailscale profile picture URL"),
        ("5", "tsTailnetId", "Tailscale tailnet ID"),
        ("6", "tsRole", "Tailscale user role"),
        ("7", "tsStatus", "Tailscale user/device status"),
        ("8", "tsAddress", "Tailscale device address"),
        ("9", "tsAllowedIp", "Tailscale allowed IP"),
        ("10", "tsExtraIp", "Tailscale extra IP"),
        ("11", "tsEndpoint", "Tailscale endpoint"),
        ("12", "tsDerp", "Tailscale DERP relay"),
        ("13", "tsClientVersion", "Tailscale client version"),
        ("14", "tsOs", "Tailscale device OS"),
        ("15", "tsName", "Tailscale device name"),
        ("16", "tsHostname", "Tailscale hostname"),
        ("17", "tsMachineKey", "Tailscale machine key"),
        ("18", "tsNodeKey", "Tailscale node key"),
        ("19", "tsCreated", "Tailscale creation time"),
        ("20", "tsLastSeen", "Tailscale last seen time"),
        ("21", "tsExpires", "Tailscale key expiry"),
        ("22", "tsNeverExpires", "Tailscale never expires flag"),
        ("23", "tsAuthorized", "Tailscale authorized state"),
        ("24", "tsIsExternal", "Tailscale external user flag"),
        ("25", "tsUpdateAvailable", "Tailscale update available flag"),
        ("26", "tsRouteAll", "Tailscale route all traffic flag"),
        ("27", "tsHasSubnet", "Tailscale has subnet routes flag"),
    ];
    for (num, name, desc) in ts_attrs {
        let is_bool = name.contains("NeverExpires")
            || name.contains("Authorized")
            || name.contains("IsExternal")
            || name.contains("UpdateAvailable")
            || name.contains("RouteAll")
            || name.contains("HasSubnet");
        let syntax = if is_bool {
            "1.3.6.1.4.1.1466.115.121.1.7" // Boolean
        } else {
            "1.3.6.1.4.1.1466.115.121.1.15" // Directory String
        };
        v.push(format!(
            "( {}.{} NAME '{}' DESC '{}' EQUALITY caseIgnoreMatch SYNTAX {} SINGLE-VALUE )",
            ts_base, num, name, desc, syntax
        ));
    }

    v
}

// ── Object Classes ──────────────────────────────────────────────────────────

/// Returns the full RFC 4512 §4.1.1 `objectClasses` definitions.
pub fn object_classes() -> Vec<String> {
    let mut v = Vec::new();

    // ── Core (RFC 4512 / 4519) ──
    v.push("( 2.5.6.0 NAME 'top' DESC 'RFC 4512: top of the superclass chain' ABSTRACT MUST objectClass )".into());
    v.push("( 2.5.6.6 NAME 'person' DESC 'RFC 4519: a person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ description $ seeAlso ) )".into());
    v.push("( 2.5.6.7 NAME 'organizationalPerson' DESC 'RFC 4519: an organizational person' SUP person STRUCTURAL MAY ( ou $ description ) )".into());
    v.push("( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' DESC 'RFC 2798: Internet Organizational Person' SUP organizationalPerson STRUCTURAL MAY ( uid $ mail $ mobile $ displayName $ givenName ) )".into());
    v.push("( 2.5.6.4 NAME 'organization' DESC 'RFC 4519: an organization' SUP top STRUCTURAL MUST o MAY ( description ) )".into());
    v.push("( 2.5.6.5 NAME 'organizationalUnit' DESC 'RFC 4519: an organizational unit' SUP top STRUCTURAL MUST ou MAY ( description ) )".into());
    v.push("( 2.5.6.14 NAME 'device' DESC 'RFC 4519: a device' SUP top STRUCTURAL MUST cn MAY ( seeAlso $ description $ ou ) )".into());

    // ── Subschema (RFC 4512 §4.2) ──
    v.push("( 2.5.20.1 NAME 'subschema' DESC 'RFC 4512: controlling subschema' AUXILIARY MAY ( objectClasses $ attributeTypes $ matchingRules $ matchingRuleUse $ ldapSyntaxes ) )".into());

    // ── dcObject (RFC 4519) ──
    v.push("( 1.3.6.1.4.1.1466.344 NAME 'dcObject' DESC 'RFC 4519: domain component object' SUP top AUXILIARY MUST dc )".into());

    // ── NIS / POSIX (RFC 2307bis) ──
    v.push("( 1.3.6.1.1.1.2.0 NAME 'posixAccount' DESC 'RFC 2307: abstraction of an account with POSIX attributes' SUP top AUXILIARY MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) MAY ( userPassword $ loginShell $ gecos $ description ) )".into());
    v.push("( 1.3.6.1.1.1.2.1 NAME 'shadowAccount' DESC 'RFC 2307: shadow password support' SUP top AUXILIARY MUST uid MAY ( shadowLastChange $ shadowMin $ shadowMax $ shadowWarning $ shadowInactive $ shadowExpire $ shadowFlag $ description ) )".into());
    v.push("( 1.3.6.1.1.1.2.2 NAME 'posixGroup' DESC 'RFC 2307: abstraction of a group of accounts' SUP top STRUCTURAL MUST ( cn $ gidNumber ) MAY ( userPassword $ memberUid $ description ) )".into());
    v.push("( 1.3.6.1.1.1.2.6 NAME 'ipHost' DESC 'RFC 2307: an IP host' SUP top AUXILIARY MUST ( cn $ ipHostNumber ) MAY ( description ) )".into());

    // ── OATH OTP ──
    let oath_oc_base = format!("{}.3", DIT0_OID_BASE);
    v.push(format!("( {}.1 NAME 'oathTOTPUser' DESC 'OATH TOTP user' SUP top AUXILIARY MAY ( oathSecret $ oathTokenIdentifier $ oathDigits $ oathTimeStep ) )", oath_oc_base));
    v.push(format!("( {}.2 NAME 'oathHOTPUser' DESC 'OATH HOTP user' SUP top AUXILIARY MAY ( oathSecret $ oathTokenIdentifier $ oathCounter $ oathDigits $ oathWindow ) )", oath_oc_base));

    // ── Sudo (1.3.6.1.4.1.15953.9.2.1) ──
    v.push("( 1.3.6.1.4.1.15953.9.2.1 NAME 'sudoRole' DESC 'Sudoer entry' SUP top STRUCTURAL MUST cn MAY ( sudoUser $ sudoHost $ sudoCommand $ sudoRunAsUser $ sudoRunAsGroup $ sudoOption $ sudoOrder $ sudoNotBefore $ sudoNotAfter $ description ) )".into());

    // ── Tailscale custom object class ──
    let ts_may = [
        "tsId",
        "tsLoginName",
        "tsDisplayName",
        "tsProfilePicUrl",
        "tsTailnetId",
        "tsRole",
        "tsStatus",
        "tsAddress",
        "tsAllowedIp",
        "tsExtraIp",
        "tsEndpoint",
        "tsDerp",
        "tsClientVersion",
        "tsOs",
        "tsName",
        "tsHostname",
        "tsMachineKey",
        "tsNodeKey",
        "tsCreated",
        "tsLastSeen",
        "tsExpires",
        "tsNeverExpires",
        "tsAuthorized",
        "tsIsExternal",
        "tsUpdateAvailable",
        "tsRouteAll",
        "tsHasSubnet",
    ]
    .join(" $ ");
    v.push(format!(
        "( {}.4.1 NAME 'tailscaleObject' DESC 'Tailscale-derived LDAP object' SUP top AUXILIARY MAY ( {} ) )",
        DIT0_OID_BASE, ts_may
    ));

    v
}

// ── Subschema subentry builder ──────────────────────────────────────────────

/// Build the `cn=Subschema` entry attributes per RFC 4512 §4.2.
/// The returned attributes are all in wire-ready `LdapPartialAttribute` form.
pub fn subschema_subentry_attributes() -> Vec<LdapPartialAttribute> {
    vec![
        LdapPartialAttribute {
            atype: "objectClass".to_string(),
            vals: vec![b"top".to_vec(), b"subschema".to_vec()],
        },
        LdapPartialAttribute {
            atype: "cn".to_string(),
            vals: vec![b"Subschema".to_vec()],
        },
        LdapPartialAttribute {
            atype: "objectClasses".to_string(),
            vals: object_classes()
                .into_iter()
                .map(|s| s.into_bytes())
                .collect(),
        },
        LdapPartialAttribute {
            atype: "attributeTypes".to_string(),
            vals: attribute_types()
                .into_iter()
                .map(|s| s.into_bytes())
                .collect(),
        },
        LdapPartialAttribute {
            atype: "matchingRules".to_string(),
            vals: matching_rules()
                .into_iter()
                .map(|s| s.into_bytes())
                .collect(),
        },
        LdapPartialAttribute {
            atype: "matchingRuleUse".to_string(),
            vals: matching_rule_use()
                .into_iter()
                .map(|s| s.into_bytes())
                .collect(),
        },
        LdapPartialAttribute {
            atype: "ldapSyntaxes".to_string(),
            vals: ldap_syntaxes()
                .into_iter()
                .map(|s| s.into_bytes())
                .collect(),
        },
    ]
}

/// Filter the subschema attributes to only those requested.
/// If `requested` is empty, returns all attributes (per RFC 4511 §4.5.1.8).
pub fn filter_subschema_attributes(requested: &[String]) -> Vec<LdapPartialAttribute> {
    let all = subschema_subentry_attributes();
    if requested.is_empty() || requested.iter().any(|a| a == "*" || a == "+") {
        return all;
    }
    all.into_iter()
        .filter(|attr| {
            requested
                .iter()
                .any(|r| r.eq_ignore_ascii_case(&attr.atype))
        })
        .collect()
}
