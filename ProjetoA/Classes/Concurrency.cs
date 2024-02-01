using System;
using System.Collections.Generic;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

public class DependencyInfo
{
    public string DependencyType { get; set; }
    public int LineNumber { get; set; }
}

/*class RaceConditionDetector : CSharpSyntaxWalker
{
    private int accessCount = 0;

    public bool HasRaceCondition { get; private set; }

    public override void VisitIdentifierName(IdentifierNameSyntax node)
    {
        // Verifica se o identificador é a variável compartilhada
        if (node.Identifier.Text == "sharedVariable")
        {
            // Incrementa o contador de acessos
            accessCount++;

            // Se houver mais de um acesso simultâneo, há uma condição de corrida
            if (accessCount > 1)
            {
                HasRaceCondition = true;
                return;
            }
        }

        // Chama o método base para continuar a travessia da árvore sintática
        base.VisitIdentifierName(node);
    }
}*/

public class ConcurrencyAnalyzer
{
    private List<DependencyInfo> dependencies = new List<DependencyInfo>();

    public List<DependencyInfo> AnalyzeConcurrencyIssues(string code)
    {
        dependencies.Clear();

        SyntaxTree syntaxTree = CSharpSyntaxTree.ParseText(code);
        AnalyzeNode(syntaxTree.GetRoot());

        return dependencies;
    }

    private void AnalyzeNode(SyntaxNode node)
    {
        //if (IsRaceCondition(node))
        //{
        //    AddDependency("Condição de Corrida", node);
        //}
        if (node is LockStatementSyntax lockStatement)
        {
            AddDependency("Travamento/Sincronização", lockStatement);
        }
        else if (IsDeadlock(node))
        {
            AddDependency("Impasse de Concorrência", node);
        }
        else if (node is AwaitExpressionSyntax)
        {
            AddDependency("Tarefas Assíncronas", node);
        }
        else if (IsConcurrentStructure(node))
        {
            AddDependency("Estrutura Concorrente", node);
        }

        foreach (var childNode in node.ChildNodes())
        {
            AnalyzeNode(childNode);
        }
    }

    private void AddDependency(string type, SyntaxNode node)
    {
        dependencies.Add(new DependencyInfo
        {
            DependencyType = type,
            LineNumber = node.GetLocation().GetLineSpan().StartLinePosition.Line + 1
        });
    }

    /*private static bool IsRaceCondition(SyntaxNode node)
    {
        // Lógica para verificar condições de corrida
        var raceConditionDetector = new RaceConditionDetector();
        raceConditionDetector.Visit(node);

        return raceConditionDetector.HasRaceCondition;
    }*/

    private static bool IsDeadlock(SyntaxNode node)
    {
        // Lógica para verificar impasses de concorrência
        if (node is LockStatementSyntax outerLock)
        {
            foreach (var childNode in outerLock.DescendantNodes())
            {
                if (childNode is LockStatementSyntax innerLock)
                {
                    // Verifica se os locks são diferentes para evitar um falso positivo
                    if (outerLock.Expression.ToString() != innerLock.Expression.ToString())
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private static bool IsConcurrentStructure(SyntaxNode node)
    {
        // Lógica para verificar estruturas concorrentes
        if (node is InvocationExpressionSyntax invocation &&
            invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
            memberAccess.Expression is IdentifierNameSyntax identifier &&
            (identifier.Identifier.Text == "ConcurrentQueue" || identifier.Identifier.Text == "ConcurrentDictionary"))
        {
            return true;
        }

        // Verificar outros métodos ou classes relacionados a concorrência
        if (node is MemberAccessExpressionSyntax memberAccessExpr &&
            memberAccessExpr.Name is IdentifierNameSyntax methodName &&
            (methodName.Identifier.Text == "Start" || methodName.Identifier.Text == "Join"))
        {
            return true;
        }

        // Adicione mais lógica conforme necessário para detectar outras estruturas concorrentes

        return false;
    }
}