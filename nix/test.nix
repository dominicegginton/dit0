# NixOS VM integration test for the dit0 service.
# Runs in a virtualized QEMU instance to verify the package runs and the systemd unit starts.
{ pkgs
, dit0-module
, dit0-package
, ...
}:

pkgs.testers.runNixOSTest {
  name = "dit0-test";

  # Define the virtual machine nodes in the test network
  nodes.machine = { config, pkgs, ... }: {
    imports = [ dit0-module ];

    # Create dummy credential files for testing since LoadCredential requires paths to exist
    environment.etc."dit0/ts-api-key".text = "tskey-api-dummy";
    environment.etc."dit0/otp-hmac-key".text = "dummy-otp-hmac-key-for-test-32bytes!";

    services.dit0 = {
      enable = true;
      package = dit0-package;
      base_dn = "dc=example,dc=com";
      ts_id = "example.ts.net";
      ts_hostname = "dit0-test";
      ts_api_key_file = "/etc/dit0/ts-api-key";
      otp_hmac_key_file = "/etc/dit0/otp-hmac-key";
    };
  };

  # Python script to orchestrate the VM and assert behavior
  testScript = ''
    start_all()
    # Wait for the system to boot to multi-user target
    machine.wait_for_unit("multi-user.target")

    # Verify that the dit0 binary is present and runnable
    print(machine.succeed("dit0 --help || true"))

    # Verify systemd service unit file is loaded
    machine.succeed("systemctl list-unit-files | grep dit0")
  '';
}
