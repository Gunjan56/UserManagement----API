from flask import Blueprint, jsonify, request
from app.model.model import Post, User
from app.main.validators.validators import Validators
from app.utils.error_response import error_response
from app.utils.success_response import success_response

search_bp = Blueprint('search', __name__)

@search_bp.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    search_type = request.args.get('type')

    validation_result = Validators.validate_search_query(query, search_type)
    if validation_result["status"] != 200:
        return jsonify(validation_result), validation_result["status"]

    if search_type == 'posts':
        posts = Post.query.filter(Post.content.like(f'%{query}%')).all()
        search_results = [post.to_json() for post in posts]
    elif search_type == 'users':
        users = User.query.filter(
            (User.username.ilike(f'%{query}%')) | (User.email.ilike(f'%{query}%'))
        ).all()
        search_results = [{'id': user.id, 'username': user.username, 'email': user.email} for user in users]
    elif search_type == 'hashtags':
        posts = Post.query.filter(Post.content.ilike(f'%#{query}%')).all()
        search_results = [post.to_json() for post in posts]
    else:
        error_response(400, 'Invalid search type')

   
    sort_by = request.args.get('sort_by')
    if sort_by:
        if sort_by == 'likes':
            search_results.sort(key=lambda x: len(x.get('likes', [])), reverse=True)
        else:
            error_response(400, 'Invalid sort_by parameter')

    return jsonify({'results': search_results}), 200
