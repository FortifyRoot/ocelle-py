from fortifyroot._vendor.traceloop.sdk.prompts.client import PromptRegistryClient


def get_prompt(key, **args):
    return PromptRegistryClient().render_prompt(key, **args)
