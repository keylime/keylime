from keylime import keylime_logging, tenant_webapp

logger = keylime_logging.init_logging("tenant_webapp")


def main():
    tenant_webapp.main()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
