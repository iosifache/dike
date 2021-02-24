import subprocess

from configuration.dike import DikeConfig


class GhidraWrapper:
    """Class running Ghidra in headless mode to extract features

    The features are extracted into a static manner, so their number is badly
    aproximated due to factors such as repetitive instructions (in which some
    opcodes or API calls appears many times) or anti-debugging techniques. These
    features consists in opcodes and API calls.
    """
    @staticmethod
    def analyse_file(full_filename: str, extract_opcodes: bool,
                     extract_api_calls: bool) -> list:
        """Analyses a file with the help of Ghidra.

        Args:
            full_filename (str): Name of the file under analysis, containing
                                 the full path too
            extract_opcodes (bool): Boolean indicating if the opcodes are
                                    extracted
            extract_api_calls (bool): Boolean indicating if the API calls are
                                      extracted

        Returns:
            list: List of the extracted features
        """
        # Run Ghidra
        ghidra_command = DikeConfig.GHIDRA_ANALYSIS_COMMAND.format(
            full_filename, extract_opcodes, extract_api_calls).split(" ")
        try:
            process = subprocess.run(ghidra_command,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     check=True)
        except:
            return [None, None]

        # Process the output
        opcodes = []
        api_calls = []
        output = process.stdout.decode("utf-8")
        for line in output.splitlines():
            line = line.rstrip()
            if line.startswith(DikeConfig.GHIDRA_ANALYSIS_OPCODES_LINE_START):
                line = line[len(DikeConfig.GHIDRA_ANALYSIS_OPCODES_LINE_START
                                ):]
                opcodes = line.split(
                    DikeConfig.GHIDRA_ANALYSIS_ITEMS_DELIMITATOR)
            elif line.startswith(DikeConfig.GHIDRA_ANALYSIS_APIS_LINE_START):
                line = line[len(DikeConfig.GHIDRA_ANALYSIS_APIS_LINE_START):]
                api_calls = line.split(
                    DikeConfig.GHIDRA_ANALYSIS_ITEMS_DELIMITATOR)

        return [opcodes, api_calls]
