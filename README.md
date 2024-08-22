# Connectly - Real-Time Chat Application

Connectly is a real-time chat application built using the MERN stack, featuring authentication, real-time messaging, image and video sharing, profile management, and user search capabilities.

## Technologies Used

- **Frontend:** Vite with React.js, Redux, Tailwind CSS
- **Backend:** Node.js, Express.js
- **Database:** MongoDB
- **Cloud Services:** Cloudinary (for storing images and video files)
- **Authentication:** JWT (JSON Web Token) for cookie-based authentication
- **Websockets:** Socket.IO for real-time communication

## Features

- **User Registration and Authentication:** Users can register and log in using JWT tokens stored in cookies.
- **Real-Time Messaging:** Utilizes Socket.IO for creating real-time chat rooms and messaging.
- **Image and Video Sharing:** Users can share images and videos seamlessly with each other.
- **Profile Management:** Users can upload and edit their profile pictures. If not uploaded, the app displays the first letter of their name and surname as the profile picture.
- **User Search:** Includes a search bar for finding other users within the chat application.
- **Responsive Design:** Ensures a seamless experience across devices.
  
## Demo

Explore Connectly live:

### Frontend

Connectly's frontend is built using React.js and Redux for state management. It provides a responsive and intuitive user interface for seamless interaction with the chat application. Key features include:

- **User Registration and Authentication:** Users can register and log in securely using JWT tokens stored in cookies.
- **Real-Time Messaging:** Utilizes Socket.IO to enable real-time communication between users, allowing instant messaging.
- **Media Sharing:** Supports image and video sharing within chat conversations, integrated with Cloudinary for efficient storage and retrieval.
- **Profile Management:** Users can upload and edit their profile pictures, with fallback to displaying the first letter of their name and surname as a profile picture if not uploaded.

Explore the frontend live: [Connectly on Netlify](https://tauqueer-connectly-chat-app.netlify.app/)

### Backend

Connectly's backend is powered by Node.js and Express.js, providing a robust server-side architecture. MongoDB serves as the database for storing user information, messages, and other application data. Key backend features include:

- **RESTful APIs:** Implements APIs for user registration, authentication, profile management, and message handling.
- **Real-Time Communication:** Integrates WebSocket and Socket.IO for establishing and managing real-time connections between clients, facilitating instant messaging functionalities.
- **Cloud Integration:** Utilizes Cloudinary for managing and storing media files (images and videos) shared within the application.
- **Deployment:** Hosted on Render for reliable server-side execution and scalability.

Explore the backend live: [Connectly on Render](https://mern-real-time-chat-app-ps9f.onrender.com)

# Connectly Postman API Collection

Explore and test the APIs of Connectly, a real-time chat application built using the MERN stack.

[Connectly Postman API Collection](https://documenter.getpostman.com/view/29969708/2sA3duGtJP)

This collection includes APIs for user registration, authentication, profile management, real-time messaging, image and video sharing, user search, and more.

Use this link to view detailed API documentation, test endpoints, and understand the functionalities of Connectly.


## How to Run Locally

To run the project locally, follow these steps:

1. Clone the repository:
   ```sh
   git clone https://github.com/tauqueeralam42/mern-real-time-chat-app.git
   ```
2. Navigate to the project directory:
   ```sh
   cd mern-real-time-chat-app
   ```
3. Install dependencies for both frontend and backend:
   ```sh
   cd frontend
    npm install
    cd ../backend
    npm install
    ```
4. Configure MongoDB:

- Ensure MongoDB is installed and running locally or provide a MongoDB URI.
- Update the MongoDB URI in the backend configuration files if necessary.

5. Start the server:
   ```sh
    cd ../backend
    npm start
   ```
6. Start the frontend:
   ```sh
    cd ../frontend
    npm start
   ```
7. Open your browser and visit http://localhost:5173 to view the application.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any changes.

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -m 'Add some feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Open a pull request.

## Contact

For any questions or suggestions, feel free to reach out.

- GitHub: [tauqueeralam42](https://github.com/tauqueeralam42)
- Email: tauqueeralam42@gmail.com.com
