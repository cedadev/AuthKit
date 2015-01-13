To use this example do the following:

1. Edit ``model.py`` to choose the database you wish to use.
   The default should be fine but you will need ``pysqlite`` installed.
   
2. Run the ``create.py`` file to create the necessary database tables::

        python create.py

3. Start the example server::

        python app.py
        
4. Visit the server at http://localhost:8080/private
