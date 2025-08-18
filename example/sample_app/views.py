from django.views.generic import TemplateView

class Index(TemplateView):
  template_name = 'sample_app/index.html'