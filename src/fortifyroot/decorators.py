"""Decorators for marking functions as workflows, tasks, agents, and tools.

These decorators allow you to create hierarchical traces of your LLM application,
making it easier to understand the flow and debug issues.

Example:
    ::

        from fortifyroot.ocelle import workflow, task

        @workflow(name="document_qa")
        def answer_question(document: str, question: str):
            chunks = split_document(document)
            relevant = find_relevant_chunks(chunks, question)
            return generate_answer(relevant, question)

        @task(name="split_document")
        def split_document(document: str):
            # Your logic here
            return chunks
"""

from typing import Any, Callable, Optional, TypeVar

from fortifyroot._vendor.tracer.sdk.decorators import (
    agent as _tl_agent,
    task as _tl_task,
    tool as _tl_tool,
    workflow as _tl_workflow,
)

F = TypeVar("F", bound=Callable[..., Any])


def task(
    name: Optional[str] = None,
    version: Optional[int] = None,
    method_name: Optional[str] = None,
) -> Callable[[F], F]:
    """
    Decorator for marking a function as a task.

    Tasks are units of work within a workflow. They create spans that help
    track the execution of individual steps in your LLM application.

    Args:
        name: Optional name for the task. Defaults to the function name.
        version: Optional version number for tracking task versions.
        method_name: If decorating a class, specify the method to wrap.

    Returns:
        A decorator that wraps the function with tracing.

    Example:
        ::

            @task(name="process_chunk")
            def process_chunk(chunk: str) -> str:
                # Process the chunk
                return processed

            @task(name="embedder", method_name="embed")
            class Embedder:
                def embed(self, text: str) -> List[float]:
                    return embeddings
    """
    return _tl_task(name=name, version=version, method_name=method_name)


def workflow(
    name: Optional[str] = None,
    version: Optional[int] = None,
    method_name: Optional[str] = None,
) -> Callable[[F], F]:
    """
    Decorator for marking a function as a workflow.

    Workflows are top-level operations that may contain multiple tasks.
    They create parent spans that group related operations together.

    Args:
        name: Optional name for the workflow. Defaults to the function name.
        version: Optional version number for tracking workflow versions.
        method_name: If decorating a class, specify the method to wrap.

    Returns:
        A decorator that wraps the function with tracing.

    Example:
        ::

            @workflow(name="document_qa")
            def answer_question(document: str, question: str) -> str:
                # Orchestrate multiple tasks
                chunks = split_document(document)
                answer = generate_answer(chunks, question)
                return answer
    """
    return _tl_workflow(name=name, version=version, method_name=method_name)


def agent(
    name: Optional[str] = None,
    version: Optional[int] = None,
    method_name: Optional[str] = None,
) -> Callable[[F], F]:
    """
    Decorator for marking a function as an agent.

    Agents are autonomous entities that can make decisions and take actions.
    Use this decorator for functions that implement agent-like behavior.

    Args:
        name: Optional name for the agent. Defaults to the function name.
        version: Optional version number for tracking agent versions.
        method_name: If decorating a class, specify the method to wrap.

    Returns:
        A decorator that wraps the function with tracing.

    Example:
        ::

            @agent(name="research_agent")
            def research_agent(query: str) -> str:
                # Agent logic with tool calls and reasoning
                return result
    """
    return _tl_agent(name=name, version=version, method_name=method_name)


def tool(
    name: Optional[str] = None,
    version: Optional[int] = None,
    method_name: Optional[str] = None,
) -> Callable[[F], F]:
    """
    Decorator for marking a function as a tool.

    Tools are functions that agents can call to perform specific actions,
    such as web searches, calculations, or API calls.

    Args:
        name: Optional name for the tool. Defaults to the function name.
        version: Optional version number for tracking tool versions.
        method_name: If decorating a class, specify the method to wrap.

    Returns:
        A decorator that wraps the function with tracing.

    Example:
        ::

            @tool(name="web_search")
            def web_search(query: str) -> List[str]:
                # Perform web search
                return results

            @tool(name="calculator")
            def calculate(expression: str) -> float:
                # Evaluate expression
                return result
    """
    return _tl_tool(name=name, version=version, method_name=method_name)


__all__ = [
    "task",
    "workflow",
    "agent",
    "tool",
]
