from gpyg import ProcessSession, Process

with ProcessSession() as session:
    process = session.spawn("gpg --card-edit --batch --status-fd 1 --command-fd 0")
    for data in process.tui("cardedit.prompt"):
        print("\n".join(data))
        process.send_line("help")