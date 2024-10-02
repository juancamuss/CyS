import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

public class LoginWindow {
    public static void main(String[] args) {
        // Crear el marco (JFrame)
        JFrame frame = new JFrame("Login");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 250);
        frame.setLocationRelativeTo(null);

        // Crear un panel para los elementos de la interfaz
        JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.fill = GridBagConstraints.HORIZONTAL;

        // Etiqueta de usuario
        JLabel userLabel = new JLabel("Usuario:");
        constraints.gridx = 0;
        constraints.gridy = 0;
        panel.add(userLabel, constraints);

        // Campo de texto para el usuario
        JTextField userText = new JTextField();
        userText.setPreferredSize(new Dimension(200, 30));
        constraints.gridx = 1;
        constraints.gridy = 0;
        panel.add(userText, constraints);

        // Etiqueta de contraseña
        JLabel passwordLabel = new JLabel("Contraseña:");
        constraints.gridx = 0;
        constraints.gridy = 1;
        panel.add(passwordLabel, constraints);

        // Campo de texto para la contraseña
        JPasswordField passwordText = new JPasswordField();
        passwordText.setPreferredSize(new Dimension(200, 30));
        constraints.gridx = 1;
        constraints.gridy = 1;
        panel.add(passwordText, constraints);

        // Botón de login
        JButton loginButton = new JButton("Login");
        loginButton.setPreferredSize(new Dimension(100, 40));
        constraints.gridx = 1;
        constraints.gridy = 2;
        constraints.anchor = GridBagConstraints.CENTER;
        panel.add(loginButton, constraints);

        // Acción al pulsar el botón de login
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Abrir nueva ventana con archivos encriptados
                showEncryptedFilesWindow();
            }
        });

        // Añadir el panel al marco
        frame.add(panel);
        frame.setVisible(true);
    }

    // Método para mostrar la ventana con archivos encriptados
    private static void showEncryptedFilesWindow() {
        JFrame encryptedFrame = new JFrame("Archivos Encriptados");
        encryptedFrame.setSize(400, 300);
        encryptedFrame.setLocationRelativeTo(null);
        encryptedFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        JPanel panel = new JPanel(new BorderLayout());

        // Simulación de archivos encriptados
        String[] encryptedFiles = {"Archivo1.enc", "Archivo2.enc", "Archivo3.enc"};
        JList<String> fileList = new JList<>(encryptedFiles);
        panel.add(new JScrollPane(fileList), BorderLayout.CENTER);

        // Botón para ir a la ventana de selección de archivos
        JButton openFileSelectorButton = new JButton("Seleccionar Archivos");
        openFileSelectorButton.setPreferredSize(new Dimension(200, 30));
        openFileSelectorButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showFileSelectorWindow();
            }
        });

        panel.add(openFileSelectorButton, BorderLayout.SOUTH);

        encryptedFrame.add(panel);
        encryptedFrame.setVisible(true);
    }

    // Método para mostrar la ventana de selección de archivos
    private static void showFileSelectorWindow() {
        JFrame fileSelectorFrame = new JFrame("Seleccionar Archivos");
        fileSelectorFrame.setSize(500, 400);
        fileSelectorFrame.setLocationRelativeTo(null);
        fileSelectorFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        // Campo para el nombre
        JTextField nameField = new JTextField();
        nameField.setPreferredSize(new Dimension(400, 30));
        panel.add(new JLabel("Nombre:"));
        panel.add(nameField);

        // Selector de archivos
        JButton selectFileButton = new JButton("Seleccionar Archivo");
        panel.add(selectFileButton);

        // Área donde se mostrarán los archivos seleccionados
        DefaultListModel<File> fileListModel = new DefaultListModel<>();
        JList<File> fileList = new JList<>(fileListModel);
        JScrollPane fileScrollPane = new JScrollPane(fileList);
        fileScrollPane.setPreferredSize(new Dimension(400, 150));
        panel.add(fileScrollPane);

        // Acción para seleccionar archivos
        selectFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setMultiSelectionEnabled(true);
                int result = fileChooser.showOpenDialog(null);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File[] selectedFiles = fileChooser.getSelectedFiles();
                    for (File file : selectedFiles) {
                        fileListModel.addElement(file);
                    }
                }
            }
        });

        // Botón de acción final
        JButton finalButton = new JButton("Procesar Archivos");
        panel.add(finalButton);

        fileSelectorFrame.add(panel);
        fileSelectorFrame.setVisible(true);
    }
}


