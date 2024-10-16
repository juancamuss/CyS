import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class prueba2 {
    private JFrame listFrame;
    private JFrame encryptFrame;
    private List<File> selectedFiles;
    private DefaultListModel<String> listModel;
    private JPanel fileListPanel;
    private JList<String> encFileList;

    public prueba2() {
        // Crear la ventana de lista de archivos
        listFrame = new JFrame("Lista de Archivos Cifrados");
        listFrame.setSize(600, 500);
        listFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        listFrame.setLocationRelativeTo(null);

        JPanel listPanel = new JPanel(new BorderLayout());
        encFileList = new JList<>(getEncFiles());
        JScrollPane encFileScrollPane = new JScrollPane(encFileList);
        JButton goToEncryptButton = new JButton("Ir a Comprimir y Cifrar");
        goToEncryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                listFrame.setVisible(false);
                encryptFrame.setVisible(true);
            }
        });
        listPanel.add(encFileScrollPane, BorderLayout.CENTER);
        listPanel.add(goToEncryptButton, BorderLayout.NORTH);
        listFrame.add(listPanel);

        // Crear la ventana de compresión y cifrado
        encryptFrame = new JFrame("Comprimir y Cifrar Archivos");
        encryptFrame.setSize(600, 500);
        encryptFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        encryptFrame.setLocationRelativeTo(null);

        JPanel encryptPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0;
        gbc.gridy = 0;

        selectedFiles = new ArrayList<>();
        listModel = new DefaultListModel<>();
        fileListPanel = new JPanel();
        fileListPanel.setLayout(new BoxLayout(fileListPanel, BoxLayout.Y_AXIS));
    }

    // Método para obtener la lista de archivos cifrados
    private DefaultListModel<String> getEncFiles() {
        DefaultListModel<String> model = new DefaultListModel<>();
        File dir = new File(System.getProperty("user.dir"));
        File[] files = dir.listFiles((d, name) -> name.endsWith(".enc"));
        if (files != null) {
            for (File file : files) {
                model.addElement(file.getName());
            }
        }
        return model;
    }

    // Método para mostrar la ventana de lista de archivos
    public void showFileListWindow() {
        listFrame.setVisible(true);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            prueba2 app = new prueba2();
            app.showFileListWindow();
        });
    }
}
