from akkoma import Akkoma 

client_id, client_secret = Akkoma.create_app(
    'app_name',
    to_file="app_clientcred.txt",
    api_base_url = 'https://infosec.place'
    )
akkoma = Akkoma(client_id = "app_clientcred.txt", api_base_url = 'https://infosec.place')

grant_type = 'password'

akkoma.log_in(
    client_id,
    client_secret,
    grant_type,
    'p0bot',
    '-----REDACTED-----',

    scopes=["write"],
    to_file = "app_usercred.txt"
)   
