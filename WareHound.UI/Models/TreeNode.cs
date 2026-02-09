namespace WareHound.UI.Models
{
    public class TreeNode
    {
        public string Text { get; set; }
        public System.Collections.ObjectModel.ObservableCollection<TreeNode> Children { get; set; } = new();

        public TreeNode(string text)
        {
            Text = text;
        }
        public TreeNode AddChild(string text)
        {
            var child = new TreeNode(text);
            Children.Add(child);
            return child;
        }
    }
}
