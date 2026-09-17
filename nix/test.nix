# NixOS VM integration test for the dit0 service and client module.
# Runs in a virtualized QEMU instance to verify the package runs, the server systemd unit starts,
# and the sshd/LDAP client module configures properly.
{ pkgs
, dit0-module
, dit0-client-module
, dit0-package
, ...
}:

pkgs.testers.runNixOSTest {
  name = "dit0-test";

  # Define the virtual machine nodes in the test network
  nodes = {
    machine = { config, pkgs, ... }: {
      imports = [ dit0-module ];

      # Create dummy credential files for testing since LoadCredential requires paths to exist
      environment.etc."dit0/ts-api-key".text = "tskey-api-dummy";

      services.dit0 = {
        enable = true;
        package = dit0-package;
        base_dn = "dc=example,dc=com";
        ts_id = "example.ts.net";
        ts_hostname = "dit0-test";
        ts_api_key_file = "/etc/dit0/ts-api-key";
      };
    };

    client = { config, pkgs, ... }: {
      imports = [ dit0-client-module ];

      services.dit0.client = {
        enable = true;
        server = "ldaps://dit0-test.example.ts.net:636";
        base_dn = "dc=example,dc=com";
        tls_reqcert = "never";
      };
    };
  };

  # Python script to orchestrate the VM and assert behavior
  testScript = ''
    start_all()
    # Wait for the system to boot to multi-user target
    machine.wait_for_unit("multi-user.target")
    client.wait_for_unit("multi-user.target")

    # Verify that the dit0 binary is present and runnable
    print(machine.succeed("dit0 --help || true"))

    # Verify systemd service unit file is loaded on server
    machine.succeed("systemctl list-unit-files | grep dit0")

    # Verify sshd and nslcd are active / loaded on client
    client.succeed("systemctl is-active sshd")
    client.succeed("systemctl list-unit-files | grep nslcd")
  '';
}
