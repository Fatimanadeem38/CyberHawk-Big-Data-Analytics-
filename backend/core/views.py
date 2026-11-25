"""Small helpers shared by the page views."""
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView


class Page(LoginRequiredMixin, TemplateView):
    """A logged-in page. Data is loaded by JavaScript from the REST APIs."""
    page_id = ""
    page_title = ""

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx.update(page_id=self.page_id, page_title=self.page_title)
        return ctx


def int_param(request, name, default, lo=0, hi=10000):
    try:
        return max(lo, min(hi, int(request.query_params.get(name, default))))
    except (TypeError, ValueError):
        return default
