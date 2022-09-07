import streamlit as st
import pickle

st.set_page_config(layout="wide")
my_slot1 = st.empty()
notes_dict = open('links.pkl', 'rb')
l=pickle.load(notes_dict)
notes_dict.close()
st.subheader("Add a New Link")
c1, c2 = st.columns([2, 4])
a=c1.text_input("Name","",key=1)
b=c2.text_input("Link","",key=2)
if st.button('Add'):
    l[a]=b

st.subheader("Delete")
a=st.text_input("Enter the Name to delete","",key=3)
if st.button('Delete'):
    del l[a]

st.subheader("Links")

for i in l :
    c1, c2 = st.columns([2, 4])
    with c1:
        st.text_input("Name",i)
    with c2:
        st.text("")
        st.write("["+l[i]+"]("+l[i]+")")
        #st.text_input("Link",l[i],key=str(i)+'a')



notes_dict = open('links.pkl', 'wb')
pickle.dump(l, notes_dict)
notes_dict.close()


