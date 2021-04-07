"""Script for opcodes and API calls extraction using Ghidra.

This script is written in Python 2 due to the constraints of the Ghidra API. It
is meant to be called from the StaticOpcodes or StaticAPIs extractors, not
directly from a terminal. The output is printed on stdout.
"""
import sys

from ghidra.util.task import TaskMonitor

# These constants needs to be synced with the parameters set in the platform
# configuration.
GHIDRA_ANALYSIS_GLOBAL_NAMESPACE = "Global"
GHIDRA_ANALYSIS_OPCODES_LINE_START = "OPCODES: "
GHIDRA_ANALYSIS_APIS_LINE_START = "APIS: "
GHIDRA_ANALYSIS_ITEMS_DELIMITATOR = ","


# Some variables are exported by the Ghidra API and their name should be in the
# camelcase format. pylint: disable=invalid-name
def delegate_ghidra(extract_opcodes, extract_api_calls):
    """Delegates Ghidra to extract opcodes or/and API calls.

    The extraction is executed in a static manner, from the current program
    under analysis and prints the results on the screen.

    The features are extracted by walking through the functions of the program
    and inspecting:
    - the code units, that are divided into executed Assembly operations; and
    - the called functions, that are verified to be in a different namespace
    than the global one (the remaining ones are largely from libraries).

    One of the boolean parameters needs to be set to true.

    Args:
        extract_opcodes (bool): Boolean indicating if the opcodes are extracted
        extract_api_calls (bool): Boolean indicating if the API calls are
                                  extracted
    """
    if (not extract_opcodes and not extract_api_calls):
        return

    # Get all functions
    # pylint: disable=undefined-variable
    function_manager = currentProgram.getFunctionManager()  # noqa
    functions = function_manager.getFunctions(True)

    # Iterate through functions
    opcodes = []
    apis = []
    for function in functions:
        listing = currentProgram.getListing()  # noqa
        function_body = function.getBody()
        codeUnits = listing.getCodeUnits(function_body, True)

        # Get the opcodes for the current function
        if extract_opcodes:
            for codeUnit in codeUnits:
                stringified_instruction = str(codeUnit.toString())
                opcodes.append(stringified_instruction.split(" ")[0].lower())

        # Get the API calls for the current function
        if extract_api_calls:
            called_functions = function.getCalledFunctions(TaskMonitor.DUMMY)

            for called_function in called_functions:
                # Save the API name if the parent namespace is not the
                # global one
                namespace = str(called_function.getParentNamespace())
                if namespace != GHIDRA_ANALYSIS_GLOBAL_NAMESPACE:
                    apis.append(str(called_function.getName()))

    if extract_opcodes:
        opcodes_str = GHIDRA_ANALYSIS_ITEMS_DELIMITATOR.join(opcodes)
        print(GHIDRA_ANALYSIS_OPCODES_LINE_START + opcodes_str)
    if extract_api_calls:
        apis_str = GHIDRA_ANALYSIS_ITEMS_DELIMITATOR.join(apis)
        print(GHIDRA_ANALYSIS_APIS_LINE_START + apis_str)


def main():
    """Main function."""
    # pylint: disable=undefined-variable
    arguments = getScriptArgs()  # noqa
    if len(arguments) != 2:
        sys.exit(1)
    extract_opcodes = (str(arguments[0]) == "True")
    extract_api_calls = (str(arguments[1]) == "True")

    delegate_ghidra(extract_opcodes, extract_api_calls)


if __name__ == "__main__":
    main()
