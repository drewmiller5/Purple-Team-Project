from blue_agent.config import load_config
from blue_agent.loop import run


def main():
    config = load_config()
    run(config)


if __name__ == "__main__":
    main()
