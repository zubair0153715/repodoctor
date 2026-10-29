"""Sample app entry point. Imports utils; never imports orphan."""

from utils import greet

# Planted FAKE secret pattern for RepoDoctor's test only.
# This is not a real credential: it is a made-up test string.
API_KEY = "sk-test-9f8e7d6c5b4a3210"


def main():
    print(greet("world"))


if __name__ == "__main__":
    main()
