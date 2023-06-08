# With Fontend : https://fakecoder.tech/funnelhq/
# Deployed URL : https://funnelhq.pythonanywhere.com

## Deatailed API Docs : https://pinkushaw.stoplight.io/docs/funnelhq/08daa5e33dfde-new-user-signup


API DOCUMENTATION:

Sign Up User :
curl --location 'https://funnelhq.pythonanywhere.com/signup' \
--header 'Content-Type: application/json' \
--data '{
    "username" : string,
    "password" : string
}'

Login User :
curl --location 'https://funnelhq.pythonanywhere.com/login' \
--header 'Content-Type: application/json' \
--data '{
    "username" : string,
    "password" : string
}'

List All Tasks for an User:
curl --location 'https://funnelhq.pythonanywhere.com/tasks' \
--header 'Authorization: token_value' \
--data ''

Add a New Task:
curl --location 'https://funnelhq.pythonanywhere.com/tasks' \
--header 'Authorization: token_value' \
--header 'Content-Type: application/json' \
--data '{
    "title" : string,
    "description" : string,
    "due_date" : string,
    "status" : string
}'

Get a Particular Task by ID:
curl --location 'https://funnelhq.pythonanywhere.com/tasks/{id}' \
--header 'Authorization: token_value' \
--data ''

Update a Particular task:
curl --location --request PUT 'https://funnelhq.pythonanywhere.com/tasks/{id}' \
--header 'Authorization: token_value' \
--header 'Content-Type: application/json' \
--data '{
    "title" : string,
    "description" : string,
    "due_date" : string,
    "status" : string
}'

Delete a Task by ID:
curl --location --request DELETE 'https://funnelhq.pythonanywhere.com/tasks/{id}' \
--header 'Authorization: token_value' \
--data ''