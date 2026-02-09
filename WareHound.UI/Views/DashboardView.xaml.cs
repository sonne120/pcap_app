using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using WareHound.UI.Models;

namespace WareHound.UI.Views;

public partial class DashboardView : UserControl
{
    public DashboardView()
    {
        InitializeComponent();
    }

    private void DataGridRow_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is DataGridRow row && row.Item is PacketInfo packet)
        {
            e.Handled = true;
            try
            {
                var detailWindow = new PacketDetailWindow(packet)
                {
                    Owner = Window.GetWindow(this)
                };
                detailWindow.ShowDialog();
            }
            catch { }
        }
    }
}
