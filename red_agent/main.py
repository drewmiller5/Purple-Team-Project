from red_agent.config import load_config
from red_agent.loop import run


def main():
    config = load_config()
    run(config)


if __name__ == "__main__":
    main()
