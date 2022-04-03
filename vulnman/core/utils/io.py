import asyncio
from vulnman.core.utils.logging import logger


class CommandStreamReader(object):
    def __init__(self, stream, target, tag, plugin, cmd, service=None, outfile=None):
        self.stream = stream
        self.plugin = plugin
        self.target = target
        self.tag = tag
        self.lines = []
        self.outfile = outfile
        self.service = service
        self.cmd = cmd
        self.ended = False

        # Empty files that already exist.
        if self.outfile:
            with open(self.outfile, 'w'):
                pass

    async def read(self):
        """
        read lines from the stream until it ends

        :return:
        """
        while True:
            if self.stream.at_eof():
                break
            try:
                line = (await self.stream.readline()).decode('utf-8').rstrip()
            except ValueError:
                logger.error(
                    '{bright}[{yellow}' + self.target.address + '{crst}/{bgreen}' + self.tag +
                    '{crst}]{rst} A line was longer than 64 KiB and cannot be processed. Ignoring.')
                continue

            if line != '':
                logger.info(
                    '{bright}[{yellow}' + self.target.address + '{crst}/{bgreen}' + self.tag + '{crst}]{rst} ' +
                    line.strip().replace('{', '{{').replace('}', '}}'), verbosity=3)
                # await self.plugin.on_new_output_line(line.strip().replace('{', '{{').replace('}', '}}'),
                #                                     self.cmd, self.target, service=self.service)

            if self.outfile is not None:
                with open(self.outfile, 'a') as writer:
                    writer.write(line + "\n")
            self.lines.append(line)
        self.ended = True
        output = "\n".join(self.lines)
        await self.plugin.on_plugin_end(output, self.cmd, self.target, service=self.service)

    async def readline(self):
        """
        read a line from the stream cache

        :return:
        """
        while True:
            try:
                return self.lines.pop(0)
            except IndexError:
                if self.ended:
                    return None
                else:
                    await asyncio.sleep(0.1)

    async def readlines(self):
        lines = []
        while True:
            line = await self.readline()
            if line is not None:
                lines.append(line)
            else:
                break
        return lines
