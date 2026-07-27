from referee.config import load_config
from referee.loop import run


def main():
    config = load_config()
    run(config)


if __name__ == "__main__":
    main()
