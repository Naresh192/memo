import streamlit as st
import pickle
from cryptography.fernet import Fernet
key = Fernet.generate_key()
# string the key in a file
with open('filekey.key', 'wb') as filekey:
   filekey.write(key)

st.set_page_config(layout="wide")
my_slot1 = st.empty()
notes_dict = open('notes_dict.pkl', 'rb')

decrypted = fernet.decrypt(notes_dict)
 
# opening the file in write mode and
# writing the decrypted data
with open('notes_dict.pkl', 'wb') as notes_dict:
    notes_dict.write(decrypted)

l=pickle.load(notes_dict)
notes_dict.close()
st.subheader("Add a New Note")
c1, c2 = st.columns([1, 4])
a=c1.text_input("Label","",key=1)
b=c2.text_input("Description","",key=2)
if st.button('Add/Update'):
    l[a]=b

st.subheader("Delete")
a=st.text_input("Enter the Label to delete","",key=3)
if st.button('Delete'):
    if a=="" :
        pass
    else :
        del l[a]

g1, g2 = st.columns([1, 4])

st.subheader("Notes")
if st.button("Refresh") :
    pass

for i in list(l.keys()) :
    c1, c2 ,c3= st.columns([1, 4,1])
    with c1:
        a=st.text_input("Label",i)
    with c2:
        st.text_input("Description",l[i],key=str(i)+'a')
    with c3:
        st.text("")
        st.text("")
        if st.button("Delete",key=str(i)+'b') :
            del l[a]

notes_dict = open('notes_dict.pkl', 'wb')
pickle.dump(l, notes_dict)

encrypted = fernet.encrypt(nums_dict)
 
# opening the file in write mode and
# writing the encrypted data
with open('notes_dict.pkl', 'wb') as encrypted_file:
    encrypted_file.write(encrypted)

notes_dict.close()


