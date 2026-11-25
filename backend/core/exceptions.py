import logging

from rest_framework.response import Response
from rest_framework.views import exception_handler

from .es import ESUnavailable

log = logging.getLogger(__name__)


def api_exception_handler(exc, context):
    if isinstance(exc, ESUnavailable):
        return Response({"detail": "Elasticsearch is not reachable right now.", "service": "elasticsearch",
                         "error": str(exc)[:300]}, status=503)
    response = exception_handler(exc, context)
    if response is None:
        log.exception("Unhandled API error", exc_info=exc)
        return Response({"detail": "Internal server error.", "error": str(exc)[:300]}, status=500)
    return response
