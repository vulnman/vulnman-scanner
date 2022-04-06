import pluginlib


@pluginlib.Parent("parser")
class ParserPlugin:

    @pluginlib.abstractmethod
    def parse(self, filepath, client):
        pass
