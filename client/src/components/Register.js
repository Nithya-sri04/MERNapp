import React ,{ useState }from 'react';
import { Link,useNavigate } from 'react-router-dom';
import avatar from '../assets/avatar_img.jpg';
import toast,{ Toaster } from 'react-hot-toast';
import { useFormik } from 'formik';
import convertToBase64 from '../help/convert';
import { registerValidation } from '../help/validate';
import styles from '../styles/Username.module.css';
import { registerUser } from '../help/helper';




export default function Register() {
  const navigate = useNavigate();
  const [file, setFile] = useState()
    const formik = useFormik({
      initialValues: {
      email: 'example@gmail.com',
      username: 'example123',
      password : 'admin@123'
      },
      validate: registerValidation,
      validateOnBlur: false,
      validateOnChange: false,
      onSubmit: async (values) => {
        values = await Object.assign(values, { profile : file || ''})
        let registerPromise = registerUser(values)
        toast.promise(registerPromise,{
          loading : 'Creating...',
          success: <b>Registered Successfully..!</b>,
          error:<b>Could not Register</b>
        })

        registerPromise.then(function(){navigate('/')})
      }
    });

  /** formik doensn't support file upload so we need to create this handler */
  const onUpload = async e => {
    const base64 = await convertToBase64(e.target.files[0]);
    setFile(base64);
  }
  
    return (
      <div className="container mx-auto">
         <Toaster position="top-center" reverseOrder={false} />
        <div className='flex justify-center items-center h-screen'>
          <div className={styles.glass} style = {{width : "45%"}}>
            <div className="title flex flex-col items-center">
              <h4 className='text-3xl font-bold '>Register Now!</h4>
              <span className='py-4 text-xl w-2/3 text-center text-gray-500'>
                Explore more by connecting with us!
              </span>
            </div>
            <form className='py-1' onSubmit={formik.handleSubmit}>
              <div className='profile flex justify-center py-4'>
                <label htmlFor = "profile">
                  <img src = {file || avatar} className = {styles.profile_img} alt = "avatar"/>
                </label>
                <input onChange = {onUpload} type = "file" id = "profile" name= 'profile'/>
              </div>
              <div className="textbox flex flex-col items-center gap-6">
                <input {...formik.getFieldProps('email')} className={styles.textbox} type="email" placeholder='Email*' />
                <input {...formik.getFieldProps('username')} className={styles.textbox} type="text" placeholder='Username*' />
                <input {...formik.getFieldProps('password')} className={styles.textbox} type="password" placeholder='Password*' />
                <button className={styles.btn} type='submit'>Register</button>
              </div>

              <div className="text-center py-4">
                <span className='text-gray-500'>Already have an account? <Link className='text-red-500' to="/">Login Now</Link></span>
              </div>
            </form>
          </div>
        </div>
      </div>
    );
  }
  
