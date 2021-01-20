#!/usr/bin/env python3

import subordinate.modules.preprocessors as preprocessors


def get_preprocessors(
    extractor: extractors._Extractor
) -> typing.List[preprocessors.PreprocessorsTypes]:
    feature_types = extractor.get_feature_types()
    available_preprocessors = extractor.get_supported_preprocessors()
    choosen_preprocessors = []
    for i in range(len(feature_types)):
        # Check if there is only one preprocessor
        if (len(available_preprocessors[i]) == 1):
            choosen_preprocessors.append(available_preprocessors[i][0])
            Logger.log_question(
                "For extractor {}, the feature \"{}\", with type {}, will have attached the preprocessor {} as it is the single one that is available."
                .format(
                    type(extractor).__name__, feature_types[i][0],
                    feature_types[i][1].name,
                    available_preprocessors[i][0].name))

        else:
            # List the extracted features and their available preprocessors
            Logger.log_question(
                "For extractor {}, a feature is \"{}\", with type {}. Available preprocessors are:"
                .format(
                    type(extractor).__name__, feature_types[i][0],
                    feature_types[i][1].name))
            for j in range(len(available_preprocessors[i])):
                Logger.log("\t{}. {}\n".format(
                    j, available_preprocessors[i][j].name))
            Logger.log("Choose one index from the options above: ", end="")

            # Let the user choose
            choosen_index = int(input())
            choosen_preprocessors.append(
                available_preprocessors[i][choosen_index])

    return choosen_preprocessors


# Create the preprocessor
choosen_preprocessors_types = get_preprocessors(extractor)
choosen_preprocessors = []
for choosen_preprocessors_type in choosen_preprocessors_types:
    # Check if the extractor is the frequency one
    specific_arguments = {}
    if (choosen_preprocessors_type is
            preprocessors.PreprocessorsTypes.GROUP_COUNTER):
        if (extractor_id == "O"):
            needed_config = config["opcodes"]
        elif (extractor_id == "A"):
            needed_config = config["apis"]
        specific_arguments = {
            "categories": needed_config["categories"],
            "min_ignored_percent": needed_config["min_ignored_percent"],
            "verbose": True
        }
    elif (choosen_preprocessors_type is
          preprocessors.PreprocessorsTypes.N_GRAMS):
        specific_arguments = {
            "n": 3,
            "to_lowercase": True,
            "valid_charset": preprocessors.NGrams.Charset.LOWERCASE
        }

    # Create a new preprocessor
    new_preprocessor = preprocessors.PreprocessorsFactory.create_preprocessor_from_type(
        choosen_preprocessors_type, specific_arguments)
    choosen_preprocessors.append(new_preprocessor)