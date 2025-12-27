from mailjet_rest import Client
import configparser

config = configparser.ConfigParser()
config.read("config.ini")

mailjet = Client(
    auth=(
        config["mailjet"]["api_key"],
        config["mailjet"]["secret_key"]
    ),
    version="v3.1"
)

response = mailjet.send.create(data={
    "Messages": [
        {
            "From": {
                "Email": config["mailjet"]["from_email"],
                "Name": "Mailjet Test"
            },
            "To": [
                {"Email": "pmcke@yahoo.com"}
            ],
            "Subject": "Mailjet test – mckellar.nz",
            "TextPart": (
                "This is a test email sent via Mailjet.\n\n"
                "If you received this, Mailjet is working correctly."
            )
        }
    ]
})

print(response.status_code)
print(response.json())
