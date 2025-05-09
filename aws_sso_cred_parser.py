import configparser
import os
import subprocess
import sys
import subprocess
import json

default_profile_config = {}


def get_correct_os_filepath(directory: str) -> None:
    if sys.platform.startswith("darwin"):
        return os.path.abspath(os.path.expanduser(directory))
    else:
        sys.exit("Unsupported OS. Please run this script on macOS")


def version_check() -> None:
    out = subprocess.Popen(
        ["aws", "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    stdout = out.communicate()[0]
    if "aws-cli" in stdout.decode():
        return
    sys.exit("AWS CLI not found. Please install AWS CLI or AWS CLI v2")


def load_config_file() -> configparser.ConfigParser:

    filename = get_correct_os_filepath("~/.aws/config")

    config = configparser.ConfigParser(interpolation=None)

    with open(filename, "r") as f:
        config.read(filename)
        return config


def remove_old_credentials() -> None:
    cachedir_path = get_correct_os_filepath("~/.aws/sso/cache")

    cache_files = [x for x in os.listdir(cachedir_path) if x.endswith(".json")]

    for filename in cache_files:
        os.remove(f"{cachedir_path}/{filename}")


def retrieve_client_token() -> str:

    cachedir_path = get_correct_os_filepath("~/.aws/sso/cache")

    cache_files = [x for x in os.listdir(cachedir_path) if x.endswith(".json")]

    for filename in cache_files:
        with open(f"{cachedir_path}/{filename}", "r") as json_file:
            blob = json.load(json_file)
            try:
                access_token = blob.get("accessToken")
            except KeyError:
                pass

    if not access_token:
        sys.exit("No access token found. Please login with 'aws sso login'.")

    return access_token


def set_default_profile_config(config_file: configparser.ConfigParser) -> None:

    if "profile default" in config_file.sections():

        config_file_default = config_file["profile default"]
        print("Found default profile. Using it as a template for other profiles.")
        default_profile_config["sso_region"] = (
            config_file_default["sso_region"]
            if "sso_region" in config_file_default
            else input("Enter your default sso_region in format such as us-east-1: ")
        )
        default_profile_config["sso_start_url"] = (
            config_file_default["sso_start_url"]
            if "sso_start_url" in config_file_default
            else input("Enter your default sso_start_url:")
        )

        default_profile_config["region"] = (
            config_file_default["region"]
            if "region" in config_file_default
            else input("Enter your default region in format such as us-west-2: ")
        )
        default_profile_config["output"] = config_file_default.get("output", "json")


def setup_missing_profile_config_element(
    config_file: configparser.ConfigParser,
    profile_long_name: str,
    profile_config: dict[str],
    missing_element: str,
):
    if missing_element in default_profile_config:
        added_element = default_profile_config[missing_element]
    else:
        print(f"\n{missing_element} not found in default profile config.")
        added_element = input(f"Enter your {missing_element}: ")

    profile_config[missing_element] = added_element
    config_file.set(profile_long_name, missing_element, "%s" % added_element)

    with open(get_correct_os_filepath(directory="~/.aws/config"), "w") as configfile:
        config_file.write(configfile)

    return profile_config


def get_profile_config(
    config_file: configparser.ConfigParser, profile: str
) -> dict[str]:
    profile_long_name = f"profile {profile}"
    config_file_profile = config_file[profile_long_name]

    profile_config = {}

    for profile_element in [
        "sso_account_id",
        "sso_role_name",
        "sso_region",
        "sso_start_url",
        "region",
        "output",
    ]:
        if profile_element in config_file_profile:
            profile_config[profile_element] = config_file_profile[profile_element]
        else:

            profile_config = setup_missing_profile_config_element(
                config_file,
                profile_long_name,
                profile_config,
                missing_element=profile_element,
            )

    return profile_config


def get_role_credentials(profile_config: dict[str], access_token: str) -> dict[str]:
    command = [
        "aws",
        "sso",
        "get-role-credentials",
        "--account-id",
        profile_config["sso_account_id"],
        "--role-name",
        profile_config["sso_role_name"],
        "--access-token",
        access_token,
        "--region",
        profile_config["sso_region"],
    ]

    out = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout = out.communicate()[0]
    return json.loads(stdout.decode())["roleCredentials"]


def refresh_profile_credentials(profile_name: str, role_credentials: dict[str]) -> None:

    credentials_path = get_correct_os_filepath(directory="~/.aws/credentials")

    creds = configparser.ConfigParser()
    creds.read(credentials_path)

    if profile_name not in creds.sections():
        creds.add_section(profile_name)

    creds.set(profile_name, "aws_access_key_id", "%s" % role_credentials["accessKeyId"])
    creds.set(
        profile_name,
        "aws_secret_access_key",
        "%s" % role_credentials["secretAccessKey"],
    )
    creds.set(
        profile_name, "aws_session_token", "%s" % role_credentials["sessionToken"]
    )

    with open(credentials_path, "w") as configfile:
        creds.write(configfile)


def process_profile(profile: str, config_file: configparser.ConfigParser) -> None:
    print(f"\n\nProcessing: {profile}")

    profile_config = get_profile_config(config_file, profile)

    os.system(f"\naws sso login --profile {profile}")
    access_token = retrieve_client_token()

    role_credentials = get_role_credentials(profile_config, access_token)
    refresh_profile_credentials(profile, role_credentials)
    print(f"Credentials for profile {profile} refreshed successfully.")


def parse_aws_creds_all_profiles() -> None:

    version_check()

    config_file = load_config_file()

    remove_old_credentials()

    set_default_profile_config(config_file)

    profiles = map(lambda item: item.replace("profile ", ""), config_file.sections())

    print(f"Refreshing credentials...")

    for profile in profiles:
        process_profile(profile, config_file)

    return


if __name__ == "__main__":
    parse_aws_creds_all_profiles()
