def sign_responses(handler, registry):
    def sign_tweens(request):
        response = handler(request)
        if hasattr(request, 'receiver'):
            content_type = response.content_type
            response.headers['Server-Authorization'] = request.receiver.respond(
                content=response.body.decode('utf-8'),
                content_type=content_type)
            response.content_type = content_type
        return response
    return sign_tweens
