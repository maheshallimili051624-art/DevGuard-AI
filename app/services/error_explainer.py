from app.schemas import ErrorExplanationRequest, ErrorExplanationResponse
from app.services.ollama_client import call_ollama, get_configured_model


def explain_error(req: ErrorExplanationRequest) -> ErrorExplanationResponse:
    model_to_use = req.model_name or get_configured_model()

    level_guide = {
        "beginner": "Explain concepts simply using analogies, avoiding unnecessary jargon, and provide clear step-by-step guidance.",
        "intermediate": "Provide practical technical insight with idiomatic solutions and concise architectural notes.",
        "advanced": "Focus on root causes, memory/concurrency internals, edge cases, and performance implications."
    }.get(req.experience_level, "Provide a clear developer-friendly explanation.")

    system_prompt = (
        "You are DevGuard AI's Error Explainer and Debugging Assistant. "
        "Analyze the provided error, stack trace, and code. "
        "Strictly adhere to the following output format sections:\n"
        "---SUMMARY---\n"
        "[A clear plain-language explanation of what happened]\n"
        "---LIKELY_CAUSES---\n"
        "- Cause 1\n- Cause 2\n"
        "---EVIDENCE_ANALYSIS---\n"
        "[Analysis of stack trace and related code line-by-line]\n"
        "---DEBUGGING_STEPS---\n"
        "1. Step one\n2. Step two\n"
        "---POSSIBLE_FIXES---\n"
        "[Code snippets and explanation of fixes]\n"
        "---SUGGESTED_TESTS---\n"
        "- Test to verify fix\n"
        "---ASSUMPTIONS_AND_UNCERTAINTIES---\n"
        "[Explicit statement of assumptions and what remains uncertain without running tests]"
    )

    prompt = (
        f"Language: {req.language}\n"
        f"Experience Level: {req.experience_level} ({level_guide})\n\n"
        f"Error Message:\n{req.error_message}\n\n"
        f"Stack Trace:\n{req.stack_trace or 'None provided'}\n\n"
        f"Related Source Code:\n```text\n{req.related_code or 'None provided'}\n```\n\n"
        f"Expected Behavior: {req.expected_behavior or 'Unspecified'}\n"
        f"Actual Behavior: {req.actual_behavior or 'Unspecified'}\n"
    )

    raw_response = call_ollama(prompt, system_prompt=system_prompt, model_name=model_to_use)

    # Defaults
    summary = raw_response
    likely_causes = ["Review the stack trace for line numbers where the exception was raised."]
    evidence_analysis = "Stack trace and code correlation analyzed by local model."
    debugging_steps = ["Reproduce with minimal input.", "Set breakpoints or logging around the error line."]
    possible_fixes = ["Inspect variables for null or uninitialized states."]
    suggested_tests = ["Run existing test suite with regression tests."]
    uncertainties = "Analysis is based on static inspection; actual runtime state was not executed."

    def extract_section(tag_start, tag_end, text):
        if tag_start in text:
            sub = text.split(tag_start)[1]
            if tag_end and tag_end in sub:
                return sub.split(tag_end)[0].strip()
            return sub.strip()
        return None

    s = extract_section("---SUMMARY---", "---LIKELY_CAUSES---", raw_response)
    if s:
        summary = s

    c = extract_section("---LIKELY_CAUSES---", "---EVIDENCE_ANALYSIS---", raw_response)
    if c:
        likely_causes = [line.strip("-* ") for line in c.splitlines() if line.strip()]

    e = extract_section("---EVIDENCE_ANALYSIS---", "---DEBUGGING_STEPS---", raw_response)
    if e:
        evidence_analysis = e

    d = extract_section("---DEBUGGING_STEPS---", "---POSSIBLE_FIXES---", raw_response)
    if d:
        debugging_steps = [line.strip("1234567890. -*") for line in d.splitlines() if line.strip()]

    f = extract_section("---POSSIBLE_FIXES---", "---SUGGESTED_TESTS---", raw_response)
    if f:
        possible_fixes = [line for line in f.splitlines() if line.strip()]

    t = extract_section("---SUGGESTED_TESTS---", "---ASSUMPTIONS_AND_UNCERTAINTIES---", raw_response)
    if t:
        suggested_tests = [line.strip("-* ") for line in t.splitlines() if line.strip()]

    u = extract_section("---ASSUMPTIONS_AND_UNCERTAINTIES---", None, raw_response)
    if u:
        uncertainties = u

    return ErrorExplanationResponse(
        summary=summary,
        likely_causes=likely_causes,
        evidence_analysis=evidence_analysis,
        debugging_steps=debugging_steps,
        possible_fixes=possible_fixes,
        suggested_tests=suggested_tests,
        uncertainties_and_assumptions=uncertainties,
        model_used=model_to_use
    )
