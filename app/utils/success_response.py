def success_response(status=None, message="Success", detail=None):
    response = {
        "status": status,
        "message": message,
        "detail": detail or message,
        
    }
    return response
