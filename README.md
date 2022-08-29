# MP-H-D
This is a version of MP-H which has been modified to run in Docker.

## How to run
To run the containers, the following steps need to be followed:
1. Install docker and docker-compose
2. Clone this repository
3. (Optional) Change the settings in `.env` and `mph.env`
4. (Optional) Remove unneeded services from `docker-compose.yml` (like unbound when not using the DNS honeypot)
5. Run `docker-compose up -d`

## How to see the results
The results are stored in a `logs` folder at the same location as the `docker-compose.yml` file.
