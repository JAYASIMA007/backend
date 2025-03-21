# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from pymongo import MongoClient
import json
import jwt
import datetime
import csv
from io import StringIO
# import google.generativeai as genai
import logging
from bson.objectid import ObjectId
from rest_framework.exceptions import AuthenticationFailed  # Import this exception
from datetime import datetime
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny  # Correct import for utcnow()
from rest_framework.response import Response
from rest_framework import status
from bson import errors


# Initialize MongoDB client
client = MongoClient("mongodb+srv://krish:krish@assessment.ar5zh.mongodb.net/")
db = client["test_portal_db"]  # Replace with your database name
collection = db["MCQ_Assessment_Data"]
section_collection = db["MCQ_Assessment_Section_Data"]  # Replace with your collection name
assessment_questions_collection = db["MCQ_Assessment_Data"]
mcq_report_collection = db["MCQ_Assessment_report"]
coding_report_collection = db["coding_report"]
staff_collection = db['staff']


logger = logging.getLogger(__name__)

SECRET_KEY = "Rahul"
JWT_SECRET = 'test'
JWT_ALGORITHM = "HS256"

from datetime import datetime, timedelta
import jwt
from django.http import JsonResponse

@csrf_exempt
def start_contest(request):
    if request.method == "POST":
        try:
            # Parse the incoming request body
            data = json.loads(request.body)
            contest_id = data.get("contestId")
            if not contest_id:
                return JsonResponse({"error": "Contest ID is required"}, status=400)
            
            # Generate a JWT token
            payload = {
                "contestId": contest_id,
                "exp": datetime.utcnow() + timedelta(hours=1),  # Token valid for 1 hour
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

            return JsonResponse({"token": token}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def get_test_date(request):
    if request.method == "GET":
        student_id = request.GET.get("student_id")
        contest_id = request.GET.get("contest_id")
        collection_result = db["MCQ_Assessment_report"]

        if not student_id or not contest_id:
            return JsonResponse({"error": "Missing student_id or contest_id"}, status=400)

        # Find the contest document with the matching contest_id
        contest = collection_result.find_one({"contest_id": contest_id})
        if not contest:
            return JsonResponse({"error": "Contest not found"}, status=404)

        # Find the student record with completed status
        student_data = next(
            (student for student in contest["students"] 
             if student["student_id"] == student_id and student["status"].lower() == "completed"),
            None
        )

        if not student_data:
            return JsonResponse({"error": "Student not found or contest not completed"}, status=404)

        # Get the finish time
        finish_time = student_data.get("finishTime", None)

        if isinstance(finish_time, str):  # If it's a string, convert it to datetime
            finish_time = datetime.strptime(finish_time, "%Y-%m-%dT%H:%M:%S.%fZ")
        elif not isinstance(finish_time, datetime):  # If it's in an unexpected format
            return JsonResponse({"error": "Invalid finish time format"}, status=500)

        return JsonResponse({"finish_time": finish_time.isoformat()})

    return JsonResponse({"error": "Invalid request method"}, status=405)

def generate_token(contest_id):
    payload = {
        "contest_id": contest_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expiration
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_token(token):
    print("Decode")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        contest_id = payload.get("contestId")  # Ensure correct key
        if not contest_id:
            raise ValueError("Invalid token: 'contestId' not found.")
        return contest_id
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired.")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token.")


from datetime import datetime

@csrf_exempt
def save_data(request):
    if request.method == "POST":
        try:
            # 1. Extract and decode the JWT token from cookies
            jwt_token = request.COOKIES.get("jwt")
            print(f"JWT Token: {jwt_token}")
            if not jwt_token:
                logger.warning("JWT Token missing in cookies")
                raise AuthenticationFailed("Authentication credentials were not provided.")

            try:
                decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                logger.info("Decoded JWT Token: %s", decoded_token)
            except jwt.ExpiredSignatureError:
                logger.error("Expired JWT Token")
                raise AuthenticationFailed("Access token has expired. Please log in again.")
            except jwt.InvalidTokenError:
                logger.error("Invalid JWT Token")
                raise AuthenticationFailed("Invalid token. Please log in again.")

            staff_id = decoded_token.get("staff_user")
            if not staff_id:
                logger.warning("Invalid payload: 'staff_user' missing")
                raise AuthenticationFailed("Invalid token payload.")

            # Fetch staff details from staff collection
            staff_details = staff_collection.find_one({"_id": ObjectId(staff_id)})
            if not staff_details:
                logger.error(f"Staff not found with ID: {staff_id}")
                return JsonResponse({"error": "Staff not found"}, status=404)

            data = json.loads(request.body)
            # Add staff details to the data
            data.update({
                "staffId": staff_id,
                "department": staff_details.get("department"),
                "college": staff_details.get("collegename"),
                "name": staff_details.get("full_name")
            })

            contest_id = data.get("contestId")
            if not contest_id:
                return JsonResponse({"error": "contestId is required"}, status=400)

            # Check if 'assessmentOverview' exists and contains the necessary fields
            if "assessmentOverview" not in data or "registrationStart" not in data["assessmentOverview"] or "registrationEnd" not in data["assessmentOverview"]:
                return JsonResponse({"error": "'registrationStart' or 'registrationEnd' is missing in 'assessmentOverview'"}, status=400)

            # Convert registrationStart and registrationEnd to datetime objects
            try:
                data["assessmentOverview"]["registrationStart"] = datetime.fromisoformat(data["assessmentOverview"]["registrationStart"])
                data["assessmentOverview"]["registrationEnd"] = datetime.fromisoformat(data["assessmentOverview"]["registrationEnd"])
            except ValueError as e:
                return JsonResponse({"error": f"Invalid date format: {str(e)}"}, status=400)

            collection.insert_one(data)
            return JsonResponse({
                "message": "Data saved successfully", 
                "contestId": contest_id,
                "staffDetails": {
                    "name": staff_details.get("full_name"),
                    "department": staff_details.get("department"),
                    "college": staff_details.get("collegename")
                }
            }, status=200)
        except Exception as e:
            logger.error(f"Error saving data: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def save_section_data(request):
    if request.method == "POST":
        try:
             # 1. Extract and decode the JWT token from cookies
            jwt_token = request.COOKIES.get("jwt")
            print(f"JWT Token: {jwt_token}")
            if not jwt_token:
                logger.warning("JWT Token missing in cookies")
                raise AuthenticationFailed("Authentication credentials were not provided.")

            try:
                decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                logger.info("Decoded JWT Token: %s", decoded_token)
            except jwt.ExpiredSignatureError:
                logger.error("Expired JWT Token")
                raise AuthenticationFailed("Access token has expired. Please log in again.")
            except jwt.InvalidTokenError:
                logger.error("Invalid JWT Token")
                raise AuthenticationFailed("Invalid token. Please log in again.")

            staff_id = decoded_token.get("staff_user")
            if not staff_id:
                logger.warning("Invalid payload: 'staff_user' missing")
                raise AuthenticationFailed("Invalid token payload.")

            data = json.loads(request.body)
            data["staffId"] = staff_id
            contest_id = data.get("contestId")
            if not contest_id:
                return JsonResponse({"error": "contestId is required"}, status=400)

            # Check if 'assessmentOverview' exists and contains the necessary fields
            if "assessmentOverview" not in data or "registrationStart" not in data["assessmentOverview"] or "registrationEnd" not in data["assessmentOverview"]:
                return JsonResponse({"error": "'registrationStart' or 'registrationEnd' is missing in 'assessmentOverview'"}, status=400)

            # Log the incoming data for debugging
            print("Incoming Data:", data)

            # Convert registrationStart and registrationEnd to datetime objects
            try:
                data["assessmentOverview"]["registrationStart"] = datetime.fromisoformat(data["assessmentOverview"]["registrationStart"])
                data["assessmentOverview"]["registrationEnd"] = datetime.fromisoformat(data["assessmentOverview"]["registrationEnd"])
            except ValueError as e:
                return JsonResponse({"error": f"Invalid date format: {str(e)}"}, status=400)

            collection.insert_one(data)
            return JsonResponse({"message": "Data saved successfully", "contestId": contest_id}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=400)


@csrf_exempt
def save_question(request):
    if request.method == "POST":
        try:
            # Validate Authorization Header
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JsonResponse({"error": "Authorization header missing or invalid."}, status=401)

            # Decode the token to get the contest_id
            token = auth_header.split(" ")[1]
            contest_id = decode_token(token)

            # Parse the request body
            data = json.loads(request.body)
            questions = data.get("questions", [])
            
            if not questions:
                return JsonResponse({"error": "No questions provided"}, status=400)

            # Check if the contest_id already exists and get the current question count
            assessment = assessment_questions_collection.find_one({"contestId": contest_id})
            if not assessment:
                # If the contest does not exist, create it with previousQuestionCount as 0
                print(f"Creating new contest entry for contest_id: {contest_id}")
                assessment_questions_collection.insert_one({
                    "contestId": contest_id,
                    "questions": [],
                    "previousQuestionCount": 0  # Initial count is 0
                })
                previous_count = 0
            else:
                # Get the current number of questions
                previous_count = len(assessment.get("questions", []))

            # Process new questions
            added_questions = []
            
            for question in questions:
                question_id = ObjectId()  # Generate a unique ObjectId for the question
                question["_id"] = question_id  # Add the ID to the question
                added_questions.append(question)

            # Save new questions to MongoDB and update previousQuestionCount
            if added_questions:
                assessment_questions_collection.update_one(
                    {"contestId": contest_id},
                    {
                        "$push": {"questions": {"$each": added_questions}},
                        "$set": {"previousQuestionCount": previous_count}  # Set previous count before adding new questions
                    }
                )

            # Convert ObjectId to string in the response
            for question in added_questions:
                question["_id"] = str(question["_id"])

            return JsonResponse({
                "message": "Questions added successfully!",
                "added_questions": added_questions,
                "previousQuestionCount": previous_count  # Optional: include in response for verification
            }, status=200)

        except ValueError as e:
            return JsonResponse({"error": str(e)}, status=401)
        except Exception as e:
            return JsonResponse({"error": f"An unexpected error occurred: {str(e)}"}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=405)


@csrf_exempt
def get_questions(request):
    if request.method == "GET":
        print("GET request received")
        try:
            # Validate Authorization Header
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                print("Authorization header missing or invalid")
                return JsonResponse({"error": "Unauthorized access"}, status=401)

            # Decode the token to get the contest_id
            token = auth_header.split(" ")[1]
            contest_id = decode_token(token)
            print(f"Decoded contest ID: {contest_id}")

            # Check if the contest exists in the database
            assessment = assessment_questions_collection.find_one({"contestId": contest_id})
            if not assessment:
                print(f"Creating new contest entry for contest_id: {contest_id}")
                assessment_questions_collection.insert_one({
                    "contestId": contest_id,
                    "questions": []
                })
                assessment = {"contestId": contest_id, "questions": []}

            # Fetch the questions
            questions = assessment.get("questions", [])
            previousQuestionCount = assessment.get("previousQuestionCount", 0)

            # Remove duplicates and count them
            unique_questions = []
            seen_questions = set()
            duplicate_count = 0

            for question in questions:
                question_key = f"{question['question']}-{'-'.join(question['options'])}"
                if question_key not in seen_questions:
                    seen_questions.add(question_key)
                    unique_questions.append(question)
                else:
                    duplicate_count += 1

            # Update the database with unique questions and the new previousQuestionCount
            new_previous_question_count = len(unique_questions)
            assessment_questions_collection.update_one(
                {"contestId": contest_id},
                {"$set": {"questions": unique_questions, "previousQuestionCount": new_previous_question_count}}
            )

            # Convert `_id` to string for JSON response
            for question in unique_questions:
                if "_id" in question:
                    question["_id"] = str(question["_id"])

            return JsonResponse({
                "questions": unique_questions,
                "duplicates_removed": duplicate_count,
                "previousQuestionCount": previousQuestionCount,
            }, status=200)

        except ValueError as e:
            print(f"Authorization error: {str(e)}")
            return JsonResponse({"error": str(e)}, status=401)
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def update_mcqquestion(request, question_id):
    if request.method == "PUT":
        try:
            # Validate Authorization Header
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JsonResponse({"error": "Authorization header missing or invalid."}, status=401)

            # Decode the token to get the contest_id
            token = auth_header.split(" ")[1]
            contest_id = decode_token(token)

            # Fetch the question from the request body
            data = json.loads(request.body)

            # Convert question_id to ObjectId
            try:
                object_id = ObjectId(question_id)  # Convert string to ObjectId
            except Exception:
                return JsonResponse({"error": "Invalid question ID format."}, status=400)

            # Update the specific question using $set
            result = assessment_questions_collection.update_one(
                {
                    "contestId": contest_id,
                    "questions._id": object_id  # Match the specific question ID
                },
                {
                    "$set": {
                        "questions.$.question": data.get("question"),
                        "questions.$.options": data.get("options"),
                        "questions.$.correctAnswer": data.get("correctAnswer"),
                        "questions.$.level": data.get("level"),
                        "questions.$.tags": data.get("tags", [])
                    }
                }
            )

            if result.matched_count == 0:
                return JsonResponse({"error": "Question not found"}, status=404)

            return JsonResponse({"message": "Question updated successfully"}, status=200)

        except Exception as e:
            return JsonResponse({"error": f"An unexpected error occurred: {str(e)}"}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def delete_question(request, question_id):
    if request.method == "DELETE":
        try:
            # Validate Authorization Header
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JsonResponse({"error": "Authorization header missing or invalid."}, status=401)

            # Decode the token to get the contest_id
            token = auth_header.split(" ")[1]
            contest_id = decode_token(token)

            # Fetch the contest data
            assessment = assessment_questions_collection.find_one({"contestId": contest_id})
            if not assessment:
                return JsonResponse({"error": "Contest not found"}, status=404)

            # Convert question_id to ObjectId
            try:
                object_id = ObjectId(question_id)
            except Exception:
                return JsonResponse({"error": "Invalid question ID format."}, status=400)

            # Find the question by ID
            question_to_delete = None
            for question in assessment.get("questions", []):
                if question["_id"] == object_id:
                    question_to_delete = question
                    break

            if not question_to_delete:
                return JsonResponse({"error": "Question not found"}, status=404)

            # Remove ALL questions with the same content
            result = assessment_questions_collection.update_one(
                {"contestId": contest_id},
                {"$pull": {"questions": {"question": question_to_delete["question"], "options": question_to_delete["options"]}}}
            )

            if result.modified_count == 0:
                return JsonResponse({"error": "Question not found"}, status=404)

            return JsonResponse({"message": "All duplicate questions deleted successfully"}, status=200)

        except Exception as e:
            return JsonResponse({"error": f"An unexpected error occurred: {str(e)}"}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)


@csrf_exempt
def update_question(request):
    if request.method == "PUT":
        try:
            token = request.headers.get("Authorization").split(" ")[1]
            contest_id = decode_token(token)

            data = json.loads(request.body)
            question_id = data.get("question_id")

            result = assessment_questions_collection.update_one(
                {
                    "contest_id": contest_id,
                    "questions.question_id": question_id,
                },
                {
                    "$set": {
                        "questions.$.questionType": data.get("questionType", "MCQ"),
                        "questions.$.question": data.get("question", ""),
                        "questions.$.options": data.get("options", []),
                        "questions.$.correctAnswer": data.get("correctAnswer", ""),
                        "questions.$.mark": data.get("mark", 0),
                        "questions.$.negativeMark": data.get("negativeMark", 0),
                        "questions.$.randomizeOrder": data.get("randomizeOrder", False),
                    }
                }
            )

            if result.matched_count == 0:
                return JsonResponse({"error": "Question not found"}, status=404)

            return JsonResponse({"message": "Question updated successfully"})
        except ValueError as e:
            return JsonResponse({"error": str(e)}, status=401)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def finish_contest(request):
    if request.method == "POST":
        try:
            # Validate Authorization Header
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JsonResponse({"error": "Authorization header missing or invalid."}, status=401)

            # Decode the token to get the contest_id
            token = auth_header.split(" ")[1]
            contest_id = decode_token(token)

            # Get the list of questions from the request body
            data = json.loads(request.body)
            questions_data = data.get("questions", [])

            if not questions_data:
                return JsonResponse({"error": "No question data provided."}, status=400)

            # Retrieve the existing entry for the contest_id
            existing_entry = collection.find_one({"contestId": contest_id})

            if existing_entry:
                # Update the existing entry with the new questions data
                collection.update_one(
                    {"contestId": contest_id},
                    {"$set": {"questions": questions_data}}  # Save the entire questions data
                )
            else:
                # If no entry exists for this contest_id, create a new one with all the question data
                collection.insert_one({
                    "contestId": contest_id,
                    "questions": questions_data,  # Store the full question data here
                    "assessmentOverview": {},  # Preserve the structure
                    "testConfiguration": {}
                })

            return JsonResponse({"message": "Contest finished successfully!"}, status=200)
        except ValueError as e:
            return JsonResponse({"error": str(e)}, status=401)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=400)


@csrf_exempt
def bulk_upload_questions(request):
    if request.method == "POST":
        try:
            # Validate Authorization Header
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JsonResponse({"error": "Authorization header missing or invalid."}, status=401)

            # Decode the token to get the contest_id
            token = auth_header.split(" ")[1]
            contest_id = decode_token(token)

            # Retrieve the uploaded file
            file = request.FILES.get("file")
            if not file:
                return JsonResponse({"error": "No file uploaded"}, status=400)

            # Parse CSV content
            file_data = file.read().decode("utf-8")
            csv_reader = csv.DictReader(StringIO(file_data))
            questions = []

            for row in csv_reader:
                try:
                    logger.debug("Processing row: %s", row)
                    # Extract and validate fields
                    mark = int(row.get("mark", 0)) if row.get("mark") else 0
                    negative_mark = int(row.get("negative_marking", 0)) if row.get("negative_marking") else 0
                    # question_id = str(uuid4())  # Generate unique ID

                    question = {
                        # "questionId": question_id,
                        "questionType": "MCQ",  # Assuming MCQ for bulk upload
                        "question": row.get("question", "").strip(),
                        "options": [
                            row.get("option_1", "").strip(),
                            row.get("option_2", "").strip(),
                            row.get("option_3", "").strip(),
                            row.get("option_4", "").strip(),
                            row.get("option_5", "").strip(),
                            row.get("option_6", "").strip(),
                        ],
                        "correctAnswer": row.get("correct_answer", "").strip(),
                        "mark": mark,
                        "negativeMark": negative_mark,
                        "randomizeOrder": False,  # Default to False
                        "level": row.get("level", "easy").strip(),  # Default level to "easy"
                        "tags": row.get("tags", "").split(",") if row.get("tags") else [],  # Convert tags to list
                    }
                    questions.append(question)
                except Exception as e:
                    logger.error("Error processing row: %s", row)
                    logger.error("Error: %s", str(e))
                    return JsonResponse({"error": f"Error in row: {row}. Details: {str(e)}"}, status=400)

            # Log the parsed questions
            logger.debug("Parsed Questions: %s", questions)

            return JsonResponse({"questions": questions}, status=200)
        except ValueError as e:
            logger.error("ValueError: %s", str(e))
            return JsonResponse({"error": str(e)}, status=401)
        except Exception as e:
            logger.error("Exception: %s", str(e))
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=400)
@csrf_exempt
def publish_mcq(request):
    if request.method == 'POST':
        try:
            # Validate Authorization Header
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JsonResponse({"error": "Authorization header missing or invalid."}, status=401)

            # Decode the token to get the contest_id
            token = auth_header.split(" ")[1]
            contest_id = decode_token(token)

            data = json.loads(request.body)
            print("contest_id: ",contest_id)

            selected_students = data.get('students', [])

            # Validate input
            if not contest_id:
                return JsonResponse({'error': 'Contest ID is required'}, status=400)
            if not isinstance(selected_students, list) or not selected_students:
                return JsonResponse({'error': 'No students selected'}, status=400)

            # Check if the contest document exists
            existing_document = collection.find_one({"contestId": contest_id})
            if not existing_document:
                return JsonResponse({'error': 'Contest not found'}, status=404)

            # Append questions and students to the existing document
            collection.update_one(
                {"contestId": contest_id},
                {
                    '$addToSet': {
                        'visible_to': {'$each': selected_students},  # Append new students
                    }
                }
            )

            return JsonResponse({'message': 'Questions and students appended successfully!'}, status=200)

        except Exception as e:
            return JsonResponse({'error': f'Error appending questions and students: {str(e)}'}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import random

@csrf_exempt
def get_mcqquestions(request, contestId):
    if request.method == "GET":
        try:
            # Find the contest/assessment document based on the contest_id
            assessment = collection.find_one({"contestId": contestId})
            if not assessment:
                return JsonResponse(
                    {"error": f"No assessment found for contestId: {contestId}"}, status=404
                )

            # Extract the test configuration
            test_configuration = assessment.get("testConfiguration", {})
            
            # Safely extract the number of questions to fetch
            questions_value = test_configuration.get("questions", 0)
            try:
                num_questions_to_fetch = int(questions_value)
            except (ValueError, TypeError):
                num_questions_to_fetch = 0  # Default to 0 if the value is invalid

            # Get the full list of questions
            questions = assessment.get("questions", [])

            if not questions:
                return JsonResponse(
                    {"error": "No questions found for the given contestId."}, status=404
                )

            # Validate the number of questions to fetch
            if num_questions_to_fetch > len(questions):
                return JsonResponse(
                    {"error": "Number of questions requested exceeds available questions."},
                    status=400,
                )

            # Shuffle questions if specified in the configuration
            if test_configuration.get("shuffleQuestions", False):
                random.shuffle(questions)

            # Select only the required number of questions
            selected_questions = questions[:num_questions_to_fetch]

            # Shuffle options for each question if specified
            for question in selected_questions:
                if question.get("randomizeOrder", False):
                    random.shuffle(question["options"])

            # Format the response
            response_data = {
                "assessmentName": assessment["assessmentOverview"].get("name"),
                "duration": test_configuration.get("duration"),
                "questions": [
                    {
                        "text": question.get("question"),
                        "options": question.get("options"),
                        "mark": question.get("mark"),
                        "negativeMark": question.get("negativeMark"),
                    }
                    for question in selected_questions
                ],
            }

            return JsonResponse(response_data, safe=False, status=200)

        except Exception as e:
            return JsonResponse(
                {"error": f"Failed to fetch MCQ questions: {str(e)}"}, status=500
            )
    else:
        return JsonResponse({"error": "Invalid request method"}, status=405)

@api_view(["GET"])
@permission_classes([AllowAny])  # Allow unauthenticated access for testing
def get_section_questions_for_contest(request, contest_id):
    """
    API to fetch questions from sections for a given contestId.
    """
    try:
        # Fetch MCQ tests where the contestId matches
        mcq_tests = list(assessment_questions_collection.find(
            {"contestId": contest_id},
            {"questions": 0, "correctAnswer": 0}  # Exclude fields not needed
        ))

        if not mcq_tests:
            return JsonResponse([], safe=False, status=200)  # Return an empty list if no tests are found

        # Extract and transform data
        formatted_data = []
        for test in mcq_tests:
            for section in test.get('sections', []):
                # Prepare duration in the required format
                duration = section.get('sectionDuration', {})
                if isinstance(duration, dict):
                    hours = duration.get('hours', 0)
                    minutes = duration.get('minutes', 0)
                else:
                    hours = duration // 60
                    minutes = duration % 60

                section_data = {
                    "sectionName": section.get('sectionName', ""),
                    "duration": {
                        "hours": str(hours),
                        "minutes": str(minutes)
                    },
                    "questions": []
                }

                # Process each question in the section
                for question in section.get('questions', []):
                    section_data["questions"].append({
                        "text": question.get("question", ""),
                        "options": question.get("options", []),
                        "mark": None,
                        "negativeMark": None
                    })

                formatted_data.append(section_data)
        return JsonResponse(formatted_data, safe=False, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
def submit_mcq_assessment(request):
    if request.method == "POST":
        try:
            # Parse incoming request data
            data = json.loads(request.body)
            print("Data: ", data)
            contest_id = data.get("contestId")
            answers = data.get("answers", {})
            fullscreen_warning = data.get("FullscreenWarning", 0)
            noise_warning = data.get("NoiseWarning", 0)
            tabswitch_warning = data.get("TabSwitchWarning", 0)
            face_warning = data.get("FaceWarning", 0)

            result_visibility = data.get("resultVisibility")
            ispublish = True if result_visibility == "Immediate release" else False

            pass_percentage = data.get("passPercentage", 50)  # Default pass percentage
            student_id = data.get("studentId")
            
            # Handle timestamps properly
            start_time = data.get("startTime")
            finish_time = data.get("finishTime")
            
            current_time = datetime.utcnow().isoformat()
            if not start_time:
                start_time = current_time
            if not finish_time:
                finish_time = current_time

            # Validate required fields
            if not contest_id:
                return JsonResponse({"error": "Contest ID is required"}, status=400)
            if not student_id:
                return JsonResponse({"error": "Student ID is required"}, status=400)

            # Check if student has already completed this assessment
            existing_report = mcq_report_collection.find_one({
                "contest_id": contest_id,
                "students": {
                    "$elemMatch": {
                        "student_id": student_id,
                        "status": "Completed"
                    }
                }
            })

            if existing_report:
                return JsonResponse({
                    "error": "You have already submitted this assessment",
                    "status": "Already_Submitted"
                }, status=400)

            # Fetch assessment from the database
            assessment = collection.find_one({"contestId": contest_id})
            if not assessment:
                return JsonResponse(
                    {"error": f"No assessment found for contestId: {contest_id}"},
                    status=404,
                )

            # Initialize counters and data
            correct_answers = 0
            total_questions = 0
            attended_questions = []
            section_summaries = {}

            # Process section-based or non-section-based questions
            sections = assessment.get("sections", [])
            
            if sections:  # Section-based logic
                for section in sections:
                    section_name = section.get("sectionName", "Unnamed Section")
                    section_questions = []
                    section_correct = 0
                    section_total = 0
                    
                    # Only process questions that exist in the student's answers for this section
                    student_section_answers = answers.get(section_name, {})
                    answered_questions = set(student_section_answers.keys())
                    
                    for question in section.get("questions", []):
                        question_text = question.get("question")
                        
                        # Skip questions that weren't presented to the student
                        if question_text not in answered_questions and question_text not in student_section_answers:
                            continue
                            
                        correct_answer = question.get("answer")
                        options = question.get("options", [])
                        student_answer = student_section_answers.get(question_text)

                        # Prepare question data with options
                        question_data = {
                            "title": question_text,
                            "section": section_name,
                            "student_answer": student_answer if student_answer is not None else "notattended",
                            "correct_answer": correct_answer,
                            "options": options  # Include options
                        }
                        
                        section_questions.append(question_data)
                        attended_questions.append(question_data)
                        
                        # Increment counters
                        section_total += 1
                        if student_answer == correct_answer:
                            correct_answers += 1
                            section_correct += 1
                        total_questions += 1
                    
                    # Only add section summary if there are questions in this section
                    if section_questions:
                        # Store section summary
                        section_summaries[section_name] = {
                            "questions": section_questions,
                            "correct": section_correct,
                            "total": section_total,
                            "percentage": (section_correct / section_total * 100) if section_total > 0 else 0
                        }
            else:  # Non-section-based logic
                questions = assessment.get("questions", [])
                non_section_questions = []
                
                # Get the set of questions that were answered or presented to the student
                answered_question_texts = set(answers.keys())
                
                for question in questions:
                    question_text = question.get("question")
                    
                    # Skip questions that weren't presented to the student
                    if question_text not in answered_question_texts:
                        continue
                        
                    correct_answer = question.get("correctAnswer")
                    options = question.get("options", [])
                    student_answer = answers.get(question_text)

                    question_data = {
                        "title": question_text,
                        "student_answer": student_answer if student_answer is not None else "notattended",
                        "correct_answer": correct_answer,
                        "options": options  # Include options
                    }
                    
                    non_section_questions.append(question_data)
                    attended_questions.append(question_data)
                    
                    # Increment counters
                    if student_answer == correct_answer:
                        correct_answers += 1
                    total_questions += 1
                
                # Store non-sectioned questions under a default section
                if non_section_questions:
                    section_summaries["Main"] = {
                        "questions": non_section_questions,
                        "correct": correct_answers,
                        "total": total_questions,
                        "percentage": (correct_answers / total_questions * 100) if total_questions > 0 else 0
                    }

            # Calculate percentage and grade
            percentage = (correct_answers / total_questions) * 100 if total_questions > 0 else 0
            grade = "Pass" if percentage >= pass_percentage else "Fail"

            # Prepare student data
            student_data = {
                "student_id": student_id,
                "status": "Completed",
                "grade": grade,
                "percentage": percentage,
                "attended_question": attended_questions,
                "section_summaries": section_summaries,  # Add section summaries
                "FullscreenWarning": fullscreen_warning,
                "NoiseWarning": noise_warning,
                "FaceWarning": face_warning,
                "TabSwitchWarning": tabswitch_warning,
                "startTime": start_time,
                "finishTime": finish_time,
                "submission_timestamp": current_time
            }

            # Insert or update report
            report = mcq_report_collection.find_one({"contest_id": contest_id})
            if not report:
                # Create a new report
                mcq_report_collection.insert_one({
                    "contest_id": contest_id,
                    "passPercentage": pass_percentage,
                    "students": [student_data],
                    "ispublish": ispublish,
                    "created_at": current_time
                })
            else:
                # Check if the student already exists in the students array
                students = report.get("students", [])
                student_found = False
                for i, student in enumerate(students):
                    if student.get("student_id") == student_id:
                        students[i] = student_data  # Replace the existing student data
                        student_found = True
                        break
                
                if not student_found:
                    students.append(student_data)

                # Update the report with modified students array
                mcq_report_collection.update_one(
                    {"contest_id": contest_id},
                    {
                        "$set": {
                            "students": students,
                            "passPercentage": pass_percentage,
                            "percentage": percentage,
                            "ispublish": ispublish,
                            "updated_at": current_time
                        }
                    }
                )

            # Return the result
            return JsonResponse({
                "contestId": contest_id,
                "grade": grade,
                "percentage": percentage,
                "passPercentage": pass_percentage,
                "sectionsCompleted": len(section_summaries)
            }, status=200)

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)    


@csrf_exempt
def get_correct_answer(request, contestId, regno):
    if request.method == "GET":
        try:
            # Fetch the contest report
            report = mcq_report_collection.find_one({"contest_id": contestId})
            if not report:
                return JsonResponse({"error": f"No report found for contest_id: {contestId}"}, status=404)

            # Find the student in the report
            student_report = next(
                (student for student in report.get("students", []) if student["student_id"] == regno), None
            )
            if not student_report:
                return JsonResponse({"error": f"No report found for student with regno: {regno}"}, status=404)

            # Fetch the contest details to get the name
            contest_details = collection.find_one({"contestId": contestId})
            if not contest_details:
                return JsonResponse({"error": f"No contest details found for contest_id: {contestId}"}, status=404)

            contest_name = contest_details.get("assessmentOverview", {}).get("name", "Unknown Contest")

            # Calculate the number of correct answers
            correct_answers = sum(
                1 for q in student_report.get("attended_question", []) if q.get("student_answer") == q.get("correct_answer")
            )
            formatted_report = {
                "correct_answers": correct_answers,
            }

            return JsonResponse(formatted_report, status=200, safe=False)

        except Exception as e:
            return JsonResponse({"error": f"Failed to fetch student report: {str(e)}"}, status=500)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def get_student_report(request, contestId, regno):
    if request.method == "GET":
        try:
            # Fetch the contest report
            report = mcq_report_collection.find_one({"contest_id": contestId})
            if not report:
                return JsonResponse({"error": f"No report found for contest_id: {contestId}"}, status=404)

            # Find the student in the report
            student_report = next(
                (student for student in report.get("students", []) if student["student_id"] == regno), None
            )
            if not student_report:
                return JsonResponse({"error": f"No report found for student with regno: {regno}"}, status=404)

            # Fetch the contest details to get the name
            contest_details = collection.find_one({"contestId": contestId})
            if not contest_details:
                return JsonResponse({"error": f"No contest details found for contest_id: {contestId}"}, status=404)

            contest_name = contest_details.get("assessmentOverview", {}).get("name", "Unknown Contest")

            # Calculate the number of correct answers
            correct_answers = sum(
                1 for q in student_report.get("attended_question", []) if q.get("student_answer") == q.get("correct_answer")
            )

            # Fetch additional data from MCQ_Assessment_Data
            assessment_data = assessment_questions_collection.find_one({"contestId": contestId})
            generate_certificate = assessment_data.get("testConfiguration", {}).get("generateCertificate", False)

            # Fetch top 5 students based on percentage
            students_scores = sorted(report.get("students", []), key=lambda x: x.get("percentage", 0), reverse=True)[:5]

            # Fetch student details from students_collection using ObjectId
            top_5_students = []
            for student in students_scores:
                try:
                    student_details = students_collection.find_one(
                        {"_id": ObjectId(student["student_id"])},
                        {"_id": 0, "name": 1, "regno": 1}
                    )
                except Exception as e:
                    student_details = None
                
                
                if student_details:
                    top_5_students.append({
                        "name": student_details.get("name", "Unknown"),
                        "regno": student_details.get("regno", "Unknown"),
                        "marks": student.get("percentage", 0)
                    })

            # Format the response
            formatted_report = {
                "contest_id": contestId,
                "contest_name": contest_name,
                "student_id": regno,
                "status": student_report.get("status"),
                "grade": student_report.get("grade"),
                "start_time": student_report.get("startTime"),
                "finish_time": student_report.get("finishTime"),
                "red_flags": student_report.get("warnings", 0),
                "fullscreen": student_report.get("FullscreenWarning", 0),
                "facewarning": student_report.get("FaceWarning", 0),
                "tabswitchwarning": student_report.get("TabSwitchWarning", 0),
                "noisewarning": student_report.get("NoiseWarning", 0),
                "attended_questions": [
                    {
                        "id": index + 1,
                        "question": q.get("title"),
                        "options": q.get("options"),
                        "userAnswer": q.get("student_answer"),
                        "correctAnswer": q.get("correct_answer"),
                        "isCorrect": q.get("student_answer") == q.get("correct_answer"),
                    }
                    for index, q in enumerate(student_report.get("attended_question", []))
                    if q.get("student_answer") is not None
                ],
                "correct_answers": correct_answers,
                "passPercentage": report.get("passPercentage", 0),
                "generateCertificate": generate_certificate,
                "top_5_students": top_5_students  # Append top 5 students
            }

            return JsonResponse(formatted_report, status=200, safe=False)

        except Exception as e:
            return JsonResponse({"error": f"Failed to fetch student report: {str(e)}"}, status=500)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=405)

@api_view(["POST"])
@permission_classes([AllowAny])  # Ensure only authorized users can access
def publish_result(request, contestId):
    try:
        # Validate the contest_id
        if not contestId:
            return JsonResponse({"error": "Contest ID is required"}, status=400)

        # Update the ispublish flag in the database
        result = mcq_report_collection.update_one(
            {"contest_id": contestId},
            {"$set": {"ispublish": True}}
        )

        if result.modified_count == 0:
            return JsonResponse({"error": "Contest not found or already published"}, status=404)

        return JsonResponse({"message": "Results published successfully"}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

from django.core.mail import send_mail
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import jwt
import json
import logging
from pymongo import MongoClient
from datetime import datetime

students_collection = db["students"]  # Assuming you have a students collection

logger = logging.getLogger(__name__)

def decode_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        contest_id = payload.get("contestId")
        if not contest_id:
            raise ValueError("Invalid token: 'contestId' not found.")
        return contest_id
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired.")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token.")

@csrf_exempt
def publish_mcq(request):
    if request.method == 'POST':
        try:
            # Validate Authorization Header
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JsonResponse({"error": "Authorization header missing or invalid."}, status=401)

            # Decode the token to get the contest_id
            token = auth_header.split(" ")[1]
            contest_id = decode_token(token)

            data = json.loads(request.body)
            print("contest_id: ", contest_id)

            selected_students = data.get('students', [])

            # Validate input
            if not contest_id:
                return JsonResponse({'error': 'Contest ID is required'}, status=400)
            if not isinstance(selected_students, list) or not selected_students:
                return JsonResponse({'error': 'No students selected'}, status=400)

            # Check if the contest document exists
            existing_document = collection.find_one({"contestId": contest_id})
            if not existing_document:
                return JsonResponse({'error': 'Contest not found'}, status=404)

            # Check if it's a section-based test
            if existing_document.get("assessmentOverview", {}).get("sectionDetails") == "Yes":
                sections = existing_document.get("sections", [])
                
                # Calculate totalMarks
                total_marks = sum(
                    int(section.get("numQuestions", 0)) * int(section.get("markAllotment", 0))
                    for section in sections
                )

                # Update the totalMarks field in MongoDB
                collection.update_one(
                    {"contestId": contest_id},
                    {"$set": {"testConfiguration.totalMarks": str(total_marks)}}
                )

            # Append students to the visible_to field
            collection.update_one(
                {"contestId": contest_id},
                {
                    '$addToSet': {
                        'visible_to': {'$each': selected_students},  # Append new students
                    }
                }
            )

            return JsonResponse({'message': 'Questions and students appended successfully!'}, status=200)

        except Exception as e:
            return JsonResponse({'error': f'Error appending questions and students: {str(e)}'}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

        
# # # Configure the model
# model = genai.GenerativeModel('gemini-1.5-pro')
# api_key = "AIzaSyA1fzr8LD2ywsBvoIt3IFm1efjbhG9GkfM"  # Ensure this API key is secure
# genai.configure(api_key=api_key)

import re  # Add this import at the top if not already present

@csrf_exempt
def generate_questions(request):
    if request.method == "POST":
        # Getting form data from JSON request body
        try:
            data = json.loads(request.body)
            topic = data.get("topic")
            subtopic = data.get("subtopic")
            num_questions_input = data.get("num_questions")
            question_type = "Multiple Choice"  # Force the question type to Multiple Choice
            level_distribution = data.get("level_distribution")
            
            # Input validation
            if not topic or not subtopic:
                return JsonResponse({"error": "Topic and subtopic are required."}, status=400)
                
            if not num_questions_input:
                return JsonResponse({"error": "Number of questions is required."}, status=400)
                
            if not level_distribution or not isinstance(level_distribution, list) or len(level_distribution) == 0:
                return JsonResponse({"error": "Level distribution is required."}, status=400)
            
            try:
                num_questions = int(num_questions_input)  # Convert the input to an integer
            except ValueError:
                return JsonResponse({"error": "Number of questions must be a valid integer."}, status=400)
            
            questions_data = []
                
            # Dictionary for mapping full level names to short forms
            level_mapping = {
                "Remembering": "L1",
                "Understanding": "L2",
                "Applying": "L3",
                "Analyzing": "L4",
                "Evaluating": "L5",
                "Creating": "L6"
            }

            # Validate total questions against level distribution
            try:
                total_count = sum(int(level_data.get('count', 0)) for level_data in level_distribution)
                if total_count != num_questions:
                    return JsonResponse({"error": f"Total questions in level distribution ({total_count}) must equal {num_questions}."}, status=400)
            except (TypeError, ValueError):
                return JsonResponse({"error": "Invalid count values in level distribution."}, status=400)

            # Process each level
            for level_data in level_distribution:
                level = level_data.get('level')
                count = int(level_data.get('count', 0))
                
                if count <= 0:
                    continue  # Skip if count is zero or negative
                
                if not level:
                    return JsonResponse({"error": "Level name is required for each distribution entry."}, status=400)
                
                # Get the corresponding short form level
                short_level = level_mapping.get(level, "Unknown")

                # Define the prompt for Multiple Choice Questions with very explicit formatting instructions
                prompt = (
                    f"Generate {count} Multiple Choice questions on the topic '{topic}' with subtopic '{subtopic}' "
                    f"for the Bloom's Taxonomy level: {level}.\n\n"
                    f"IMPORTANT FORMATTING RULES:\n"
                    f"1. Each question MUST have EXACTLY 4 options (no more, no less)\n"
                    f"2. Each question must be formatted EXACTLY like this example:\n"
                    f"Question: What is the capital of France?\n"
                    f"Options: Paris;London;Berlin;Madrid\n"
                    f"Answer: Paris\n"
                    f"Negative Marking: 0\n"
                    f"Mark: 1\n"
                    f"Level: {level}\n"
                    f"Tags: Geography,Europe,Capitals\n\n"
                    f"3. Do not include A), B), C), D) or any numbering in the options\n"
                    f"4. Separate the options with semicolons only\n"
                    f"5. The correct answer MUST be exactly identical to one of the options\n"
                    f"6. Separate different questions with a blank line\n"
                    f"7. Do not include any explanation or additional text"
                )

                try:
                    # # # Request to Gemini AI (Google Generative AI)
                    # response = model.generate_content(prompt)

                    # # # # Extract the text content from the response
                    # question_text = response._result.candidates[0].content.parts[0].text

                    # Check if the response is empty or malformed
                    if not question_text.strip():
                        return JsonResponse({"error": "No questions generated. Please try again."}, status=500)

                    # Split questions by double newline
                    questions_list = re.split(r'\n\s*\n', question_text.strip())
                    
                    # Process each question
                    for question in questions_list:
                        try:
                            # Split the question into lines
                            lines = question.strip().split('\n')
                            
                            # Check if we have enough lines for a complete question
                            if len(lines) < 6:
                                print(f"Skipping incomplete question: {question}")
                                continue
                            
                            # Process question text
                            question_line = lines[0]
                            question_text = question_line.replace("Question:", "", 1).strip() if question_line.startswith("Question:") else question_line
                            
                            # Process options
                            options_line = lines[1]
                            options_text = options_line.replace("Options:", "", 1).strip() if options_line.startswith("Options:") else options_line
                            options = [opt.strip() for opt in options_text.split(";")]
                            
                            # Ensure we have exactly 4 options
                            if len(options) > 4:
                                options = options[:4]
                            elif len(options) < 4:
                                # If less than 4 options, add dummy options to make it 4
                                while len(options) < 4:
                                    options.append(f"Option {len(options) + 1}")
                            
                            # Process answer
                            answer_line = lines[2]
                            answer = answer_line.replace("Answer:", "", 1).strip() if answer_line.startswith("Answer:") else answer_line
                            
                            # Ensure the answer is one of the options
                            if answer not in options:
                                # Try to find a matching option
                                answer_match = False
                                for i, opt in enumerate(options):
                                    if answer.lower() in opt.lower() or opt.lower() in answer.lower():
                                        answer = opt  # Use the exact text from the option
                                        answer_match = True
                                        break
                                
                                if not answer_match:
                                    # If no match, use the first option as the answer
                                    answer = options[0]
                            
                            # Process negative marking
                            neg_mark_line = lines[3]
                            neg_mark = neg_mark_line.replace("Negative Marking:", "", 1).strip() if neg_mark_line.startswith("Negative Marking:") else neg_mark_line
                            
                            # Process mark value
                            mark_line = lines[4]
                            mark = mark_line.replace("Mark:", "", 1).strip() if mark_line.startswith("Mark:") else mark_line
                            
                            # Process level - IMPORTANT: Use the requested level, not what AI returns
                            # This ensures consistency between what was requested and what's stored                            
                            
                            # Process tags if available
                            tags = []
                            if len(lines) > 6:
                                tags_line = lines[6]
                                tags_text = tags_line.replace("Tags:", "", 1).strip() if tags_line.startswith("Tags:") else tags_line
                                tags = [tag.strip() for tag in tags_text.split(",")]
                            
                            # Add the question to our collected data
                            # IMPORTANT: Use short_level from the request, not what AI generates
                            questions_data.append({
                                "topic": topic,
                                "subtopic": subtopic,
                                "level": short_level,  # Use the short level code directly
                                "question_type": question_type,
                                "question": question_text,
                                "options": options,
                                "correctAnswer": answer,
                                "negativeMarking": neg_mark,
                                "mark": mark,
                                "tags": tags
                            })
                            
                            print(f"Successfully processed question: {question_text[:30]}... with level {short_level}")
                            
                        except Exception as e:
                            print(f"Error processing question: {str(e)}\nQuestion text: {question[:100]}...")
                            # Continue to next question instead of failing the whole batch
                            continue
                    
                except Exception as e:
                    return JsonResponse({"error": f"Error generating questions for level {level}: {str(e)}"}, status=500)
            
            # Check if we generated any questions
            if not questions_data:
                return JsonResponse({"error": "No valid questions were generated. Please try a different topic or level."}, status=500)
            
            # Log some stats
            print(f"Successfully generated {len(questions_data)} questions across {len(level_distribution)} levels")
            
            # Return the generated questions
            return JsonResponse({
                "success": "Questions generated successfully",
                "questions": questions_data
            })

        except Exception as e:
            print(f"Top-level error in generate_questions: {str(e)}")
            return JsonResponse({"error": f"Error generating questions: {str(e)}"}, status=500)

    return JsonResponse({"error": "Invalid request method."}, status=405)


@csrf_exempt
def save_assessment_questions(request):
    if request.method == "POST":
        try:
            # Get JWT token from cookies
            jwt_token = request.COOKIES.get("jwt")
            if not jwt_token:
                return JsonResponse({"error": "Authentication required"}, status=401)

            try:
                decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                staff_id = decoded_token.get("staff_user")
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                return JsonResponse({"error": "Invalid or expired token"}, status=401)

            # Parse request data
            data = json.loads(request.body)
            section_name = data.get('sectionName')
            num_questions = data.get('numQuestions')
            section_duration = data.get('sectionDuration')
            mark_allotment = data.get('markAllotment')
            pass_percentage = data.get('passPercentage')
            time_restriction = data.get('timeRestriction')
            questions = data.get('questions', [])

            if not questions:
                return JsonResponse({"error": "No questions provided"}, status=400)

            # Find the latest assessment for this staff
            assessment = collection.find_one(
                {"staffId": staff_id},
                sort=[("_id", -1)]
            )

            if not assessment:
                return JsonResponse({"error": "No assessment found"}, status=404)

            # Format questions as per your schema
            formatted_questions = [{
                "question_type": "Multiple Choice",
                "question": q["question"],
                "options": q["options"],
                "answer": q["correctAnswer"] if "correctAnswer" in q else q["answer"]
            } for q in questions]

            # Update the document
            result = collection.update_one(
                {"_id": assessment["_id"]},
                {
                    "$push": {
                        "sections": {
                            "sectionName": section_name,
                            "numQuestions": num_questions,
                            "sectionDuration": section_duration,
                            "markAllotment": mark_allotment,
                            "passPercentage": pass_percentage,
                            "timeRestriction": time_restriction,
                            "questions": formatted_questions
                        }
                    },
                    "$inc": {"no_of_section": 1}
                }
            )

            if result.modified_count == 0:
                return JsonResponse({"error": "Failed to update assessment"}, status=400)

            return JsonResponse({
                "success": True,
                "message": "Questions saved successfully",
                "sectionName": section_name
            })

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Method not allowed"}, status=405)

@api_view(['DELETE'])
@permission_classes([AllowAny])
def delete_contest_by_id(request, contest_id):
    try:
        result = collection.delete_one({'contestId': contest_id})
        if result.deleted_count > 0:
            return Response({'message': 'Contest deleted successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Contest not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@csrf_exempt
@permission_classes(["DELETE"])
def reassign(request, contest_id, student_id):
    try:
        # Find the contest document
        contest = mcq_report_collection.find_one({"contest_id": contest_id})
        if not contest:
            return JsonResponse({"error": "Contest not found"}, status=404)

        # Filter out the student from the 'students' array
        updated_students = [s for s in contest.get("students", []) if s["student_id"] != student_id]

        # Update the document in MongoDB
        result = mcq_report_collection.update_one(
            {"contest_id": contest_id},
            {"$set": {"students": updated_students}}
        )

        if result.modified_count > 0:
            return JsonResponse({"success": True, "message": "Student reassigned successfully"})
        else:
            return JsonResponse({"error": "Student not found or no changes made"}, status=400)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    
@csrf_exempt
def close_session(request, contest_id):
    if request.method == "POST":
        try:
            result = collection.update_one(
                {"contestId": contest_id},  
                {"$set": {"Overall_Status": "closed"}}
            )

            if result.modified_count > 0:  # Use modified_count instead of matched_count
                return JsonResponse({"message": "Session closed successfully."}, status=200)
            else:
                return JsonResponse({"message": "Contest ID not found or already closed."}, status=404)

        except Exception as e:
            return JsonResponse({"message": f"Internal server error: {str(e)}"}, status=500)

    return JsonResponse({"message": "Invalid request method."}, status=405)


certificate_collection = db['certificate']

@csrf_exempt
def store_certificate(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            unique_id = data.get('uniqueId')
            student_name = data.get('studentName')
            contest_name = data.get('contestName')
            student_id = data.get('studentId')

            certificate_data = {
                'uniqueId': unique_id,
                'studentName': student_name,
                'contestName': contest_name,
                'studentId': student_id
            }

            certificate_collection.insert_one(certificate_data)
            return JsonResponse({'status': 'success', 'message': 'Certificate data stored successfully.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return super().default(o)

@csrf_exempt
def verify_certificate(request, unique_id=None):
    
    if request.method == 'GET' and unique_id:
        try:
            certificate = certificate_collection.find_one({'uniqueId': unique_id})
            if certificate:
                return JsonResponse({'status': 'success', 'certificate': certificate}, encoder=CustomJSONEncoder)
            else:
                return JsonResponse({'status': 'error', 'message': 'Certificate not found.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            unique_id = data.get('unique_id')
            certificate = certificate_collection.find_one({'uniqueId': unique_id})
            if certificate:
                return JsonResponse({'status': 'success', 'certificate': certificate}, encoder=CustomJSONEncoder)
            else:
                return JsonResponse({'status': 'error', 'message': 'Certificate not found.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})


@api_view(['PUT'])
@permission_classes([AllowAny])
def update_assessment(request, contest_id):
    """
    Endpoint to update an existing assessment.
    """
    try:
        # 1. Extract and decode the JWT token from cookies
        jwt_token = request.COOKIES.get("jwt")
        print(f"JWT Token: {jwt_token}")
        if not jwt_token:
            logger.warning("JWT Token missing in cookies")
            raise AuthenticationFailed("Authentication credentials were not provided.")

        try:
            decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            logger.info("Decoded JWT Token: %s", decoded_token)
        except jwt.ExpiredSignatureError:
            logger.error("Expired JWT Token")
            raise AuthenticationFailed("Access token has expired. Please log in again.")
        except jwt.InvalidTokenError:
            logger.error("Invalid JWT Token")
            raise AuthenticationFailed("Invalid token. Please log in again.")

        staff_id = decoded_token.get("staff_user")
        if not staff_id:
            logger.warning("Invalid payload: 'staff_user' missing")
            raise AuthenticationFailed("Invalid token payload.")

        # 2. Validate staff existence in MongoDB
        try:
            staff = staff_collection.find_one({"_id": ObjectId(staff_id)})
        except errors.InvalidId:
            logger.error("Invalid staff_id format in token")
            raise AuthenticationFailed("Invalid token payload.")

        if not staff:
            logger.error("Staff not found with ID: %s", staff_id)
            return JsonResponse({"error": "Staff not found"}, status=404)

        # 3. Retrieve the assessment from MongoDB
        assessment = assessment_questions_collection.find_one({"contestId": contest_id})
        if not assessment:
            logger.warning("Assessment not found with contestId: %s", contest_id)
            return JsonResponse({"error": "Assessment not found"}, status=404)

        # 4. Parse the request data
        data = request.data
        logger.info(f"Update Payload: {data}")

        assessment_overview = data.get("assessmentOverview", {})
        test_configuration = data.get("testConfiguration", {})

        # 5. Validate date format
        try:
            registration_start = str_to_datetime(assessment_overview.get("registrationStart"))
            registration_end = str_to_datetime(assessment_overview.get("registrationEnd"))
        except ValueError as e:
            logger.error("Invalid date format for registrationStart or registrationEnd: %s", str(e))
            return JsonResponse({"error": "Invalid date format. Use ISO format for dates."}, status=400)

        # 6. Update the assessment document
        updated_fields = {
            "assessmentOverview": {
                "name": assessment_overview.get("name", assessment["assessmentOverview"]["name"]),
                "description": assessment_overview.get("description", assessment["assessmentOverview"]["description"]),
                "registrationStart": registration_start if registration_start else assessment["assessmentOverview"]["registrationStart"],
                "registrationEnd": registration_end if registration_end else assessment["assessmentOverview"]["registrationEnd"],
                "guidelines": assessment_overview.get("guidelines", assessment["assessmentOverview"]["guidelines"]),
                "sectionDetails": assessment_overview.get("sectionDetails", assessment["assessmentOverview"].get("sectionDetails", "No")),
                "timingType": assessment_overview.get("timingType", assessment["assessmentOverview"]["timingType"]),
            },
            "testConfiguration": {
                "questions": test_configuration.get("questions", assessment["testConfiguration"]["questions"]),
                "totalMarks": test_configuration.get("totalMarks", assessment["testConfiguration"]["totalMarks"]),  # Include totalMarks
                "duration": test_configuration.get("duration", assessment["testConfiguration"]["duration"]),
                "fullScreenMode": test_configuration.get("fullScreenMode", assessment["testConfiguration"]["fullScreenMode"]),
                "faceDetection": test_configuration.get("faceDetection", assessment["testConfiguration"]["faceDetection"]),
                "deviceRestriction": test_configuration.get("deviceRestriction", assessment["testConfiguration"]["deviceRestriction"]),
                "noiseDetection": test_configuration.get("noiseDetection", assessment["testConfiguration"]["noiseDetection"]),
                "passPercentage": test_configuration.get("passPercentage", assessment["testConfiguration"]["passPercentage"]),
                "resultVisibility": test_configuration.get("resultVisibility", assessment["testConfiguration"]["resultVisibility"]),
                "fullScreenModeCount": test_configuration.get("fullScreenModeCount", assessment["testConfiguration"].get("fullScreenModeCount", 0)),  # Include fullScreenModeCount
                "faceDetectionCount": test_configuration.get("faceDetectionCount", assessment["testConfiguration"].get("faceDetectionCount", 0)),  # Include faceDetectionCount
                "noiseDetectionCount": test_configuration.get("noiseDetectionCount", assessment["testConfiguration"].get("noiseDetectionCount", 0)),  # Include noiseDetectionCount
                "shuffleQuestions": test_configuration.get("shuffleQuestions", assessment["testConfiguration"].get("shuffleQuestions", False)),  # Include shuffleQuestions
                "shuffleOptions": test_configuration.get("shuffleOptions", assessment["testConfiguration"].get("shuffleOptions", False)),  # Include shuffleOptions
            },
            "updatedAt": datetime.utcnow(),
        }

        # 7. Update the document in MongoDB
        result = assessment_questions_collection.update_one(
            {"contestId": contest_id},
            {"$set": updated_fields}
        )

        if result.modified_count == 0:
            logger.warning("No assessment modified with contestId: %s", contest_id)
            return JsonResponse({"message": "No changes were applied"}, status=200)

        logger.info("Assessment document updated: %s", contest_id)

        # 8. Return success response
        return JsonResponse({"message": "Assessment updated successfully!"}, status=200)

    except AuthenticationFailed as auth_error:
        logger.warning("Authentication failed: %s", str(auth_error))
        return JsonResponse({"error": str(auth_error)}, status=401)
    except Exception as e:
        logger.exception("Unexpected error occurred")
        return JsonResponse({"error": str(e)}, status=500)  # Include the actual error message for debugging

    
from datetime import datetime
def str_to_datetime(date_str):
    if not date_str or date_str == 'T':
        # If the date string is empty or just contains 'T', return None or raise an error
        raise ValueError(f"Invalid datetime format: {date_str}")

    try:
        # Try parsing the full datetime format (with seconds)
        return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        try:
            # If there's no seconds, try parsing without seconds
            return datetime.strptime(date_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            # If both parsing methods fail, raise an error
            raise ValueError(f"Invalid datetime format: {date_str}")# Create Assessment (POST method)

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})
