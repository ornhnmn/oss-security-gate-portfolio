import yaml
import requests


def load_config():
    content = """
service:
  name: banking-api
  environment: development
  debug: false
"""

    return yaml.safe_load(content)


def create_http_session():
    session = requests.Session()
    session.verify = True

    return session


def main():
    config = load_config()
    session = create_http_session()

    print("=" * 50)
    print("OSS Security Gate - Sample Application")
    print("=" * 50)

    print("Service:", config["service"]["name"])
    print("Environment:", config["service"]["environment"])
    print("Debug:", config["service"]["debug"])
    print("PyYAML Version:", yaml.__version__)
    print("Requests Version:", requests.__version__)
    print("TLS Verification:", session.verify)

    session.close()


if __name__ == "__main__":
    main()
