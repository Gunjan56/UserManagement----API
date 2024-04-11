def error_response(error_code, detail=None):    
    response = {
        "error_code":error_code,
        "detail": detail,
        "status": False
    }    
    return response
