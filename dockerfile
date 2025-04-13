FROM ruby:3.0.6

# Install dependencies for Ruby
RUN apt-get update -qq && apt-get upgrade -y 

# Install gem json
RUN gem install json

# Now copy all files from current directory to /app in the container
# We will make a mount point for logs. Logs will be stored locally 
# In logs/, we need to mount logs/ to docker's /app/logs
COPY . /app


# Set the working directory
WORKDIR /app

# Expose the port
EXPOSE 8081

# Run the command
CMD ["ruby", "main.rb"]