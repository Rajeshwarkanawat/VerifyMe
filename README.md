# 📌 Authentication-Based Application (MERN Stack)  

## 🚀 Overview  
This application is a robust authentication system built with the **MERN Stack (MongoDB, Express, React, Node.js)**. It provides user authentication through:  
- **JWT (JSON Web Tokens)**  
- **Email Verification (via OTP)**  
- **Database Check (User data validation)**  

---

## ✨ Features  
1. **User Registration & Login:**  
   - New users can register with their name, email, and password.  
   - Existing users can log in with valid credentials.  
   - JWT tokens are generated and stored in cookies for authentication.  

2. **Email Verification:**  
   - Users receive a 6-digit OTP on their email upon registration.  
   - The OTP is stored in the database and compared when the user submits it for verification.  

3. **Password Reset:**  
   - Users can reset their password by receiving an OTP via email.  
   - Once verified, they can update their password.  

4. **User Authentication (Middleware):**  
   - Protects routes by validating JWT tokens and extracting user details from cookies.  

5. **User Management:**  
   - Fetches user data and displays it if authenticated.  

6. **Context API & State Management (Frontend):**  
   - Uses React Context API to manage user authentication state across the app.  

7. **Responsive Design & User Experience:**  
   - Smooth navigation using React Router and Axios for backend communication.  
   - Clean UI built with Tailwind CSS.  

---

## 🛠 Tech Stack  
**Frontend:** React, Axios, React Router, Context API, Tailwind CSS  
**Backend:** Node.js, Express, Mongoose, Nodemailer  
**Database:** MongoDB  
**Authentication:** JWT, Cookies  
**Environment Management:** .env files (Backend & Frontend)  

---

## 📄 How It Works  
1. **User Registers:**  
   - Data saved in the database, JWT token generated, stored in cookies.  
   - OTP sent to user’s email for verification.  

2. **User Logs In:**  
   - Credentials verified, JWT token generated, and stored in cookies.  

3. **User Verification & Password Reset:**  
   - OTP generated, stored, and compared during email verification or password reset.  

4. **User Data Management:**  
   - Displayed on the frontend via protected routes.  

---

## 📌 Endpoints (Backend)  
- `POST /register` - Register new users.  
- `POST /login` - Authenticate existing users.  
- `POST /logout` - Destroy user session.  
- `POST /verify` - Verify email OTP.  
- `POST /resetpassword` - Reset user password via OTP.  

---

## 📌 Frontend Pages  
- **Home:** Display user information if authenticated.  
- **Login/SignUp:** Toggle between login and sign-up forms.  
- **Email Verification:** OTP submission form.  
- **Reset Password:** Multi-step process to reset the password.  

---



